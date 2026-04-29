"""LangGraph orchestration for the agentic security scan."""

from __future__ import annotations

import os
from pathlib import Path

from langgraph.graph import END, StateGraph

from difend.diff import CodeDiff
from difend.agents.cache import AgenticScanCache, CacheKey, context_hash
from difend.agents.classifier import classify_diff
from difend.agents.context import expand_context, prepare_scan_context
from difend.agents.feedback import (
    FeedbackStore,
    apply_feedback,
    apply_manual_review_feedback,
)
from difend.agents.gates import run_automated_gates
from difend.agents.handoff import run_handoff
from difend.agents.model import (
    DEFAULT_MODEL,
    AgentNodeError,
    ModelConfigurationError,
    StructuredModelClient,
)
from difend.agents.reasoning import run_security_reasoning
from difend.agents.schemas import (
    AgentExecution,
    AgentGraphState,
    AgentStatus,
    AgenticScanResult,
    DiffClassifierResult,
    ExpandedContext,
    HandoffResult,
    RiskArea,
)
from difend.agents.scoring import decide_status, merge_results, risk_score
from difend.config import load_environment


class AgenticScanError(RuntimeError):
    """Raised when the agentic scan cannot produce a trusted result."""


def run_agentic_scan(
    repository_path: Path,
    diff: CodeDiff,
    model: str | None = None,
    model_client: StructuredModelClient | None = None,
    use_cache: bool = True,
) -> AgenticScanResult:
    load_environment(repository_path)
    model_name = model or DEFAULT_MODEL
    scan_context = prepare_scan_context(diff)
    feedback_store = FeedbackStore(repository_path)
    feedback_digest = feedback_store.digest()
    cache = AgenticScanCache(repository_path)
    cache_key = CacheKey(
        diff_hash=scan_context.diff_hash,
        context_hash=context_hash(scan_context.model_dump(mode="json")),
        model=model_name,
        feedback_digest=feedback_digest,
    )

    if use_cache:
        cached = cache.get(cache_key)
        if cached is not None:
            cached.cache_hit = True
            return cached

    try:
        client = model_client or _optional_model_client()
        graph = build_graph()
        final_state = graph.invoke(
            {
                "repository_path": repository_path,
                "model": model_name,
                "patch": scan_context.patch,
                "scan_context": scan_context,
                "agents": [],
                "metadata": {
                    "model_client": client,
                    "feedback_records": feedback_store.load(),
                },
            }
        )
    except (ModelConfigurationError, AgentNodeError) as exc:
        raise AgenticScanError(str(exc)) from exc

    result = _result_from_state(final_state)
    if use_cache and scan_context.has_changes:
        cache.set(cache_key, result)
    return result


def build_graph():
    graph = StateGraph(AgentGraphState)
    graph.add_node("prepare_scan_context", _prepare_scan_context)
    graph.add_node("diff_classifier", _diff_classifier)
    graph.add_node("orchestrator_route", _orchestrator_route)
    graph.add_node("automated_gates", _automated_gates)
    graph.add_node("context_expansion", _context_expansion)
    graph.add_node("security_reasoning", _security_reasoning)
    graph.add_node("orchestrator_merge", _orchestrator_merge)
    graph.add_node("handoff", _handoff)
    graph.add_node("orchestrator_finalize", _orchestrator_finalize)

    graph.set_entry_point("prepare_scan_context")
    graph.add_edge("prepare_scan_context", "diff_classifier")
    graph.add_edge("diff_classifier", "orchestrator_route")
    graph.add_edge("orchestrator_route", "automated_gates")
    graph.add_edge("automated_gates", "context_expansion")
    graph.add_conditional_edges(
        "context_expansion",
        _reasoning_route,
        {
            "security_reasoning": "security_reasoning",
            "orchestrator_merge": "orchestrator_merge",
        },
    )
    graph.add_edge("security_reasoning", "orchestrator_merge")
    graph.add_edge("orchestrator_merge", "handoff")
    graph.add_edge("handoff", "orchestrator_finalize")
    graph.add_edge("orchestrator_finalize", END)
    return graph.compile()


def _prepare_scan_context(state: AgentGraphState) -> AgentGraphState:
    context = state["scan_context"]
    agents = list(state.get("agents", []))
    agents.append(
        AgentExecution(
            name="prepare_scan_context",
            status=AgentStatus.COMPLETED,
            detail=f"Prepared {len(context.changed_files)} changed file(s).",
        )
    )
    return {"agents": agents}


def _diff_classifier(state: AgentGraphState) -> AgentGraphState:
    metadata = state.get("metadata", {})
    client = metadata.get("model_client")
    classifier, execution = classify_diff(state["scan_context"], client)
    return {
        "classifier": classifier,
        "agents": [*state.get("agents", []), execution],
    }


def _orchestrator_route(state: AgentGraphState) -> AgentGraphState:
    classifier = state.get("classifier") or DiffClassifierResult(
        risk_areas=[RiskArea.LOW_RISK]
    )
    return {
        "agents": [
            *state.get("agents", []),
            AgentExecution(
                name="orchestrator_route",
                status=AgentStatus.COMPLETED,
                detail="Automated Gates will run; Security Reasoning is conditional.",
            ),
        ],
        "classifier": classifier,
    }


def _automated_gates(state: AgentGraphState) -> AgentGraphState:
    metadata = state.get("metadata", {})
    client = metadata.get("model_client")
    gates, execution = run_automated_gates(state["scan_context"], client)
    return {
        "gates": gates,
        "agents": [*state.get("agents", []), execution],
    }


def _context_expansion(state: AgentGraphState) -> AgentGraphState:
    expanded = expand_context(
        state["repository_path"],
        state["scan_context"],
        state["classifier"],
    )
    return {
        "expanded_context": expanded,
        "agents": [
            *state.get("agents", []),
            AgentExecution(
                name="context_expansion",
                status=AgentStatus.COMPLETED,
                detail=f"Expanded {len(expanded.files)} context file(s).",
            ),
        ],
    }


def _reasoning_route(state: AgentGraphState) -> str:
    classifier = state["classifier"]
    if classifier.should_run_security_reasoning:
        return "security_reasoning"
    return "orchestrator_merge"


def _security_reasoning(state: AgentGraphState) -> AgentGraphState:
    metadata = state.get("metadata", {})
    client = metadata.get("model_client")
    manual_review, execution = run_security_reasoning(
        state["scan_context"],
        state["classifier"],
        state["gates"],
        state.get("expanded_context", ExpandedContext()),
        client,
    )
    return {
        "manual_review": manual_review,
        "agents": [*state.get("agents", []), execution],
    }


def _orchestrator_merge(state: AgentGraphState) -> AgentGraphState:
    metadata = state.get("metadata", {})
    feedback_records = metadata.get("feedback_records", [])
    merged_findings, merged_review = merge_results(
        state["gates"].findings,
        state.get("manual_review", []),
    )
    active_findings, suppressed_findings = apply_feedback(
        merged_findings,
        feedback_records,
    )
    active_review, suppressed_review = apply_manual_review_feedback(
        merged_review,
        feedback_records,
    )
    score = risk_score(active_findings, active_review)
    status = decide_status(active_findings, active_review)
    return {
        "gates": state["gates"].model_copy(update={"findings": active_findings}),
        "manual_review": active_review,
        "suppressed_findings": suppressed_findings,
        "suppressed_manual_review": suppressed_review,
        "risk_score": score,
        "status": status,
        "agents": [
            *state.get("agents", []),
            AgentExecution(
                name="orchestrator_merge",
                status=AgentStatus.COMPLETED,
                detail="Merged outputs, enforced priority, and removed overlap.",
            ),
        ],
    }


def _handoff(state: AgentGraphState) -> AgentGraphState:
    metadata = state.get("metadata", {})
    client = metadata.get("model_client")
    handoff, execution = run_handoff(
        state["scan_context"],
        state["classifier"],
        state["gates"].findings,
        state.get("manual_review", []),
        state["status"],
        client,
    )
    return {
        "handoff": handoff,
        "agents": [*state.get("agents", []), execution],
    }


def _orchestrator_finalize(state: AgentGraphState) -> AgentGraphState:
    return {
        "agents": [
            *state.get("agents", []),
            AgentExecution(
                name="orchestrator_finalize",
                status=AgentStatus.COMPLETED,
                detail=f"Final status: {state['status']}.",
            ),
        ],
    }


def _result_from_state(state: AgentGraphState) -> AgenticScanResult:
    return AgenticScanResult(
        status=state["status"],
        scan_context=state["scan_context"],
        classifier=state.get("classifier", DiffClassifierResult()),
        expanded_context=state.get("expanded_context", ExpandedContext()),
        gates=state["gates"],
        manual_review=state.get("manual_review", []),
        suppressed_findings=state.get("suppressed_findings", []),
        suppressed_manual_review=state.get("suppressed_manual_review", []),
        handoff=state.get("handoff", HandoffResult()),
        risk_score=state.get("risk_score", 0),
        agents=state.get("agents", []),
        model=state.get("model", DEFAULT_MODEL),
        cache_hit=state.get("cache_hit", False),
    )


def _optional_model_client() -> StructuredModelClient | None:
    if os.getenv("OPENAI_API_KEY"):
        return StructuredModelClient.from_environment(required=True)
    return None
