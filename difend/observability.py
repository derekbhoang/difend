"""Runtime progress and structured observability events for scans."""

from __future__ import annotations

import sys
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any, TextIO

from pydantic import BaseModel, Field


class ScanEvent(BaseModel):
    """One structured event emitted by a scan phase."""

    timestamp: str
    command: str
    phase: str
    status: str
    progress_percent: int
    message: str = ""
    used_llm: bool = False
    duration_ms: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanObserver:
    """Collect scan events and optionally render terminal progress."""

    def __init__(
        self,
        command: str,
        phases: Sequence[str],
        *,
        display: bool = False,
        stream: TextIO | None = None,
        default_metadata: dict[str, Any] | None = None,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self.command = command
        self.phases = list(phases)
        self.display = display
        self.stream = stream or sys.stdout
        self.default_metadata = dict(default_metadata or {})
        self._clock = clock
        self._starts: dict[str, float] = {}
        self._events: list[ScanEvent] = []
        self._last_percent = 0

    @property
    def events(self) -> list[ScanEvent]:
        return list(self._events)

    def event_dicts(self) -> list[dict[str, Any]]:
        return [event.model_dump(mode="json") for event in self._events]

    def add_default_metadata(self, metadata: dict[str, Any]) -> None:
        self.default_metadata.update(metadata)

    def start_run(self, message: str = "Scan started.") -> ScanEvent:
        return self._emit(
            phase="scan",
            status="started",
            progress_percent=0,
            message=message,
        )

    def start(self, phase: str) -> None:
        self._starts[phase] = self._clock()

    def complete(
        self,
        phase: str,
        message: str = "",
        *,
        used_llm: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> ScanEvent:
        return self._finish(
            phase=phase,
            status="completed",
            message=message,
            used_llm=used_llm,
            metadata=metadata,
        )

    def skip(
        self,
        phase: str,
        message: str = "",
        *,
        metadata: dict[str, Any] | None = None,
    ) -> ScanEvent:
        return self._finish(
            phase=phase,
            status="skipped",
            message=message,
            metadata=metadata,
        )

    def fail(
        self,
        phase: str,
        message: str = "",
        *,
        metadata: dict[str, Any] | None = None,
    ) -> ScanEvent:
        return self._finish(
            phase=phase,
            status="failed",
            message=message,
            metadata=metadata,
        )

    def record_agent(
        self,
        agent,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> ScanEvent:
        status = getattr(agent.status, "value", str(agent.status))
        if status == "skipped":
            return self.skip(agent.name, agent.detail, metadata=metadata)
        if status == "failed":
            return self.fail(agent.name, agent.detail, metadata=metadata)
        return self.complete(
            agent.name,
            agent.detail,
            used_llm=bool(agent.used_llm),
            metadata=metadata,
        )

    def _finish(
        self,
        phase: str,
        status: str,
        message: str,
        used_llm: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> ScanEvent:
        started_at = self._starts.pop(phase, None)
        duration_ms = 0
        if started_at is not None:
            duration_ms = int((self._clock() - started_at) * 1000)
        return self._emit(
            phase=phase,
            status=status,
            progress_percent=self._progress_for(phase),
            message=message,
            used_llm=used_llm,
            duration_ms=duration_ms,
            metadata=metadata,
        )

    def _emit(
        self,
        phase: str,
        status: str,
        progress_percent: int,
        message: str = "",
        used_llm: bool = False,
        duration_ms: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> ScanEvent:
        merged_metadata = dict(self.default_metadata)
        merged_metadata.update(metadata or {})
        event = ScanEvent(
            timestamp=datetime.now(UTC).isoformat(),
            command=self.command,
            phase=phase,
            status=status,
            progress_percent=progress_percent,
            message=message,
            used_llm=used_llm,
            duration_ms=duration_ms,
            metadata=merged_metadata,
        )
        self._events.append(event)
        self._last_percent = max(self._last_percent, progress_percent)
        if self.display:
            self._print_event(event)
        return event

    def _progress_for(self, phase: str) -> int:
        if phase not in self.phases:
            return self._last_percent
        phase_number = self.phases.index(phase) + 1
        return round((phase_number / len(self.phases)) * 100)

    def _print_event(self, event: ScanEvent) -> None:
        label = f"{event.phase} {event.status}"
        if event.message:
            label = f"{label} - {event.message}"
        progress = format_progress_bar(event.progress_percent)
        print(
            f"{progress} {event.progress_percent}% {label}",
            file=self.stream,
        )


def format_progress_bar(percent: int, width: int = 16) -> str:
    bounded = max(0, min(100, percent))
    filled = round(width * bounded / 100)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


SCAN_PHASES = (
    "diff_capture",
    "prepare_scan_context",
    "automated_gates",
    "orchestrator_merge",
    "handoff",
    "orchestrator_finalize",
    "bundle_write",
)

AGENT_SCAN_PHASES = (
    "diff_capture",
    "prepare_scan_context",
    "diff_classifier",
    "orchestrator_route",
    "context_expansion",
    "cache_lookup",
    "automated_gates",
    "security_reasoning",
    "orchestrator_merge",
    "handoff",
    "orchestrator_finalize",
    "bundle_write",
)
