"""LangGraph orchestration for the agentic security scan."""

from __future__ import annotations

import os
from pathlib import Path

from langgraph.graph import END, StateGraph

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
from difend.diff import CodeDiff
from difend.observability import ScanObserver


class AgenticScanError(RuntimeError):
    """Raised when the agentic scan cannot produce a trusted result."""


def run_agentic_scan(
    repository_path: Path,
    diff: CodeDiff,
    model: str | None = None,
    model_client: StructuredModelClient | None = None,
    use_cache: bool = True,
    observer: ScanObserver | None = None,
) -> AgenticScanResult:
    load_environment(repository_path)
    model_name = model or DEFAULT_MODEL
    scan_context = prepare_scan_context(diff)
    feedback_store = FeedbackStore(repository_path)
    feedback_digest = feedback_store.digest()
    cache = AgenticScanCache(repository_path)

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
                "feedback_digest": feedback_digest,
                "trace": {},
                "metadata": {
                    "model_client": client,
                    "feedback_records": feedback_store.load(),
                    "feedback_digest": feedback_digest,
                    "cache": cache,
                    "use_cache": use_cache,
                    "observer": observer,
                },
            }
        )
    except (ModelConfigurationError, AgentNodeError) as exc:
        raise AgenticScanError(str(exc)) from exc

    result = _result_from_state(final_state)
    if use_cache and scan_context.has_changes and not result.cache_hit and result.cache_key:
        cache.set_by_digest(result.cache_key, result)
    return result


def build_graph():
    graph = StateGraph(AgentGraphState)
    graph.add_node("prepare_scan_context", _prepare_scan_context)
    graph.add_node("diff_classifier", _diff_classifier)
    graph.add_node("orchestrator_route", _orchestrator_route)
    graph.add_node("context_expansion", _context_expansion)
    graph.add_node("cache_lookup", _cache_lookup)
    graph.add_node("automated_gates", _automated_gates)
    graph.add_node("security_reasoning", _security_reasoning)
    graph.add_node("orchestrator_merge", _orchestrator_merge)
    graph.add_node("handoff", _handoff)
    graph.add_node("orchestrator_finalize_cached", _orchestrator_finalize_cached)
    graph.add_node("orchestrator_finalize", _orchestrator_finalize)

    graph.set_entry_point("prepare_scan_context")
    graph.add_edge("prepare_scan_context", "diff_classifier")
    graph.add_edge("diff_classifier", "orchestrator_route")
    graph.add_edge("orchestrator_route", "context_expansion")
    graph.add_edge("context_expansion", "cache_lookup")
    graph.add_conditional_edges(
        "cache_lookup",
        _cache_route,
        {
            "cache_hit": "orchestrator_finalize_cached",
            "cache_miss": "automated_gates",
        },
    )
    graph.add_conditional_edges(
        "automated_gates",
        _reasoning_route,
        {
            "security_reasoning": "security_reasoning",
            "orchestrator_merge": "orchestrator_merge",
        },
    )
    graph.add_edge("security_reasoning", "orchestrator_merge")
    graph.add_edge("orchestrator_merge", "handoff")
    graph.add_edge("handoff", "orchestrator_finalize")
    graph.add_edge("orchestrator_finalize_cached", END)
    graph.add_edge("orchestrator_finalize", END)
    return graph.compile()


def _prepare_scan_context(state: AgentGraphState) -> AgentGraphState:
    _start_event(state, "prepare_scan_context")
    context = state["scan_context"]
    execution = AgentExecution(
        name="prepare_scan_context",
        status=AgentStatus.COMPLETED,
        detail=f"Prepared {len(context.changed_files)} changed file(s).",
    )
    _record_agent_event(
        state,
        execution,
        metadata={
            "changed_files": len(context.changed_files),
            "added_lines": len(context.added_lines),
        },
    )
    return {
        "agents": [*state.get("agents", []), execution],
        "trace": _trace_update(
            state,
            "prepare_scan_context",
            {"scan_context": context.model_dump(mode="json")},
        ),
    }


def _diff_classifier(state: AgentGraphState) -> AgentGraphState:
    _start_event(state, "diff_classifier")
    metadata = state.get("metadata", {})
    client = metadata.get("model_client")
    classifier, execution = classify_diff(state["scan_context"], client)
    _record_agent_event(
        state,
        execution,
        metadata={
            "risk_areas": [area.value for area in classifier.risk_areas],
            "sensitive_files": len(classifier.sensitive_files),
            "should_run_security_reasoning": classifier.should_run_security_reasoning,
        },
    )
    return {
        "classifier": classifier,
        "agents": [*state.get("agents", []), execution],
        "trace": _trace_update(
            state,
            "diff_classifier",
            {"result": classifier.model_dump(mode="json")},
        ),
    }


def _orchestrator_route(state: AgentGraphState) -> AgentGraphState:
    _start_event(state, "orchestrator_route")
    classifier = state.get("classifier") or DiffClassifierResult(
        risk_areas=[RiskArea.LOW_RISK]
    )
    route = (
        "security_reasoning"
        if classifier.should_run_security_reasoning
        else "merge_after_gates"
    )
    execution = AgentExecution(
        name="orchestrator_route",
        status=AgentStatus.COMPLETED,
        detail="Automated Gates will run; Security Reasoning is conditional.",
    )
    _record_agent_event(
        state,
        execution,
        metadata={
            "risk_areas": [area.value for area in classifier.risk_areas],
            "route": route,
        },
    )
    return {
        "agents": [*state.get("agents", []), execution],
        "classifier": classifier,
        "trace": _trace_update(
            state,
            "orchestrator_route",
            {
                "risk_areas": [area.value for area in classifier.risk_areas],
                "should_run_security_reasoning": (
                    classifier.should_run_security_reasoning
                ),
                "route": route,
            },
        ),
    }


def _context_expansion(state: AgentGraphState) -> AgentGraphState:
    _start_event(state, "context_expansion")
    expanded = expand_context(
        state["repository_path"],
        state["scan_context"],
        state["classifier"],
    )
    execution = AgentExecution(
        name="context_expansion",
        status=AgentStatus.COMPLETED,
        detail=f"Expanded {len(expanded.files)} context file(s).",
    )
    _record_agent_event(
        state,
        execution,
        metadata={
            "context_files": len(expanded.files),
            "total_bytes": expanded.total_bytes,
            "truncated": expanded.truncated,
        },
    )
    return {
        "expanded_context": expanded,
        "agents": [*state.get("agents", []), execution],
        "trace": _trace_update(
            state,
            "context_expansion",
            {"expanded_context": expanded.model_dump(mode="json")},
        ),
    }


def _cache_lookup(state: AgentGraphState) -> AgentGraphState:
    _start_event(state, "cache_lookup")
    metadata = state.get("metadata", {})
    feedback_digest = metadata.get("feedback_digest", state.get("feedback_digest", ""))
    expanded_context = state.get("expanded_context", ExpandedContext())
    expanded_hash = context_hash(expanded_context.model_dump(mode="json"))
    cache_key = CacheKey(
        diff_hash=state["scan_context"].diff_hash,
        context_hash=expanded_hash,
        model=state["model"],
        feedback_digest=feedback_digest,
    )
    cache_digest = cache_key.digest()
    use_cache = bool(metadata.get("use_cache", True))
    cache = metadata.get("cache")
    cached_result = None
    cache_reason = "disabled"

    if not state["scan_context"].has_changes:
        cache_reason = "no_diff_not_cached"
    elif use_cache and cache is not None:
        cached_result = cache.get_by_digest(cache_digest)
        cache_reason = "hit" if cached_result else "miss"

    execution = AgentExecution(
        name="cache_lookup",
        status=AgentStatus.COMPLETED,
        detail=f"Cache {cache_reason}.",
    )
    trace_payload = {
        "cache_key": cache_digest,
        "context_hash": expanded_hash,
        "feedback_digest": feedback_digest,
        "use_cache": use_cache,
        "hit": cached_result is not None,
        "reason": cache_reason,
    }
    _record_agent_event(state, execution, metadata=trace_payload)
    result: AgentGraphState = {
        "agents": [*state.get("agents", []), execution],
        "cache_key": cache_digest,
        "context_hash": expanded_hash,
        "feedback_digest": feedback_digest,
        "cache_hit": cached_result is not None,
        "trace": _trace_update(state, "cache_lookup", trace_payload),
    }
    if cached_result is not None:
        result["cached_result"] = cached_result
    return result


def _cache_route(state: AgentGraphState) -> str:
    if state.get("cached_result") is not None:
        return "cache_hit"
    return "cache_miss"


def _automated_gates(state: AgentGraphState) -> AgentGraphState:
    _start_event(state, "automated_gates")
    metadata = state.get("metadata", {})
    client = metadata.get("model_client")
    gates, execution = run_automated_gates(state["scan_context"], client)
    _record_agent_event(
        state,
        execution,
        metadata={
            "candidates": len(gates.candidates),
            "findings": len(gates.findings),
            "rejected_llm_outputs": len(gates.rejected_llm_outputs),
        },
    )
    if not state["classifier"].should_run_security_reasoning:
        _skip_event(
            state,
            "security_reasoning",
            "Classifier did not route contextual security reasoning.",
        )
    return {
        "gates": gates,
        "agents": [*state.get("agents", []), execution],
        "trace": _trace_update(
            state,
            "automated_gates",
            {
                "candidates": [
                    candidate.model_dump(mode="json")
                    for candidate in gates.candidates
                ],
                "llm_validation": (
                    gates.llm_validation.model_dump(mode="json")
                    if gates.llm_validation
                    else None
                ),
                "rejected_llm_outputs": gates.rejected_llm_outputs,
                "findings": [
                    finding.model_dump(mode="json") for finding in gates.findings
                ],
            },
        ),
    }


def _reasoning_route(state: AgentGraphState) -> str:
    classifier = state["classifier"]
    if classifier.should_run_security_reasoning:
        return "security_reasoning"
    return "orchestrator_merge"


def _security_reasoning(state: AgentGraphState) -> AgentGraphState:
    _start_event(state, "security_reasoning")
    metadata = state.get("metadata", {})
    client = metadata.get("model_client")
    manual_review, execution, raw_result = run_security_reasoning(
        state["scan_context"],
        state["classifier"],
        state["gates"],
        state.get("expanded_context", ExpandedContext()),
        client,
    )
    _record_agent_event(
        state,
        execution,
        metadata={"manual_review": len(manual_review)},
    )
    return {
        "manual_review": manual_review,
        "agents": [*state.get("agents", []), execution],
        "trace": _trace_update(
            state,
            "security_reasoning",
            {
                "raw_output": (
                    raw_result.model_dump(mode="json")
                    if raw_result is not None
                    else None
                ),
                "manual_review": [
                    item.model_dump(mode="json") for item in manual_review
                ],
            },
        ),
    }


def _orchestrator_merge(state: AgentGraphState) -> AgentGraphState:
    _start_event(state, "orchestrator_merge")
    metadata = state.get("metadata", {})
    feedback_records = metadata.get("feedback_records", [])
    merged_findings, merged_review, covered_review = merge_results(
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
    execution = AgentExecution(
        name="orchestrator_merge",
        status=AgentStatus.COMPLETED,
        detail="Merged outputs, enforced priority, and removed overlap.",
    )
    _record_agent_event(
        state,
        execution,
        metadata={
            "active_findings": len(active_findings),
            "active_manual_review": len(active_review),
            "covered_manual_review": len(covered_review),
            "suppressed_findings": len(suppressed_findings),
            "suppressed_manual_review": len(suppressed_review),
            "risk_score": score,
            "status": status,
        },
    )
    return {
        "gates": state["gates"].model_copy(update={"findings": active_findings}),
        "manual_review": active_review,
        "covered_manual_review": covered_review,
        "suppressed_findings": suppressed_findings,
        "suppressed_manual_review": suppressed_review,
        "risk_score": score,
        "status": status,
        "agents": [*state.get("agents", []), execution],
        "trace": _trace_update(
            state,
            "orchestrator_merge",
            {
                "active_findings": [
                    finding.finding_id for finding in active_findings
                ],
                "active_manual_review": [
                    item.manual_review_id for item in active_review
                ],
                "covered_manual_review": [
                    item.model_dump(mode="json") for item in covered_review
                ],
                "suppressed_findings": [
                    finding.model_dump(mode="json")
                    for finding in suppressed_findings
                ],
                "suppressed_manual_review": [
                    item.model_dump(mode="json") for item in suppressed_review
                ],
                "risk_score": score,
                "status": status,
            },
        ),
    }


def _handoff(state: AgentGraphState) -> AgentGraphState:
    _start_event(state, "handoff")
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
    _record_agent_event(
        state,
        execution,
        metadata={
            "inspect_next": len(handoff.inspect_next),
            "codex_tasks": len(handoff.codex_tasks),
            "checklist": len(handoff.checklist),
        },
    )
    return {
        "handoff": handoff,
        "agents": [*state.get("agents", []), execution],
        "trace": _trace_update(
            state,
            "handoff",
            {"handoff": handoff.model_dump(mode="json")},
        ),
    }


def _orchestrator_finalize(state: AgentGraphState) -> AgentGraphState:
    _start_event(state, "orchestrator_finalize")
    execution = AgentExecution(
        name="orchestrator_finalize",
        status=AgentStatus.COMPLETED,
        detail=f"Final status: {state['status']}.",
    )
    _record_agent_event(
        state,
        execution,
        metadata={"status": state["status"], "cache_hit": False},
    )
    return {
        "agents": [*state.get("agents", []), execution],
        "trace": _trace_update(
            state,
            "orchestrator_finalize",
            {"status": state["status"], "cache_hit": False},
        ),
    }


def _orchestrator_finalize_cached(state: AgentGraphState) -> AgentGraphState:
    for phase in (
        "automated_gates",
        "security_reasoning",
        "orchestrator_merge",
        "handoff",
    ):
        _skip_event(
            state,
            phase,
            "Skipped because a cached scan result was reused.",
            metadata={"cache_hit": True},
        )

    _start_event(state, "orchestrator_finalize")
    cached = state["cached_result"]
    execution = AgentExecution(
        name="orchestrator_finalize",
        status=AgentStatus.COMPLETED,
        detail=f"Final status from cache: {cached.status}.",
    )
    _record_agent_event(
        state,
        execution,
        metadata={"status": cached.status, "cache_hit": True},
    )
    trace = _trace_update(
        state,
        "orchestrator_finalize",
        {
            "status": cached.status,
            "cache_hit": True,
            "cached_trace": cached.trace,
        },
    )
    return {
        "agents": [*state.get("agents", []), execution],
        "trace": trace,
        "cache_hit": True,
    }


def _result_from_state(state: AgentGraphState) -> AgenticScanResult:
    if state.get("cached_result") is not None:
        cached = state["cached_result"]
        return cached.model_copy(
            update={
                "cache_hit": True,
                "agents": state.get("agents", cached.agents),
                "cache_key": state.get("cache_key", cached.cache_key),
                "context_hash": state.get("context_hash", cached.context_hash),
                "feedback_digest": state.get(
                    "feedback_digest",
                    cached.feedback_digest,
                ),
                "trace": state.get("trace", cached.trace),
            }
        )

    return AgenticScanResult(
        status=state["status"],
        scan_context=state["scan_context"],
        classifier=state.get("classifier", DiffClassifierResult()),
        expanded_context=state.get("expanded_context", ExpandedContext()),
        gates=state["gates"],
        manual_review=state.get("manual_review", []),
        covered_manual_review=state.get("covered_manual_review", []),
        suppressed_findings=state.get("suppressed_findings", []),
        suppressed_manual_review=state.get("suppressed_manual_review", []),
        handoff=state.get("handoff", HandoffResult()),
        risk_score=state.get("risk_score", 0),
        agents=state.get("agents", []),
        model=state.get("model", DEFAULT_MODEL),
        cache_hit=state.get("cache_hit", False),
        cache_key=state.get("cache_key", ""),
        context_hash=state.get("context_hash", ""),
        feedback_digest=state.get("feedback_digest", ""),
        trace=state.get("trace", {}),
    )


def _trace_update(
    state: AgentGraphState,
    node_name: str,
    payload: dict,
) -> dict[str, object]:
    trace = dict(state.get("trace", {}))
    trace[node_name] = payload
    return trace


def _start_event(state: AgentGraphState, phase: str) -> None:
    observer = _observer(state)
    if observer is not None:
        observer.start(phase)


def _record_agent_event(
    state: AgentGraphState,
    execution: AgentExecution,
    *,
    metadata: dict[str, object] | None = None,
) -> None:
    observer = _observer(state)
    if observer is not None:
        observer.record_agent(execution, metadata=metadata)


def _skip_event(
    state: AgentGraphState,
    phase: str,
    message: str,
    *,
    metadata: dict[str, object] | None = None,
) -> None:
    observer = _observer(state)
    if observer is not None:
        observer.skip(phase, message, metadata=metadata)


def _observer(state: AgentGraphState) -> ScanObserver | None:
    metadata = state.get("metadata", {})
    return metadata.get("observer")


def _optional_model_client() -> StructuredModelClient | None:
    if os.getenv("OPENAI_API_KEY"):
        return StructuredModelClient.from_environment(required=True)
    return None
