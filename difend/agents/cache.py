"""Filesystem cache for agentic scan results."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from difend.agents.gates import GATES_VERSION
from difend.agents.prompts import PROMPT_VERSION
from difend.agents.schemas import AgenticScanResult, SCHEMA_VERSION
from difend.agents.utils import stable_hash


@dataclass(frozen=True)
class CacheKey:
    diff_hash: str
    context_hash: str
    model: str
    feedback_digest: str

    def digest(self) -> str:
        return stable_hash(
            json.dumps(
                {
                    "diff_hash": self.diff_hash,
                    "context_hash": self.context_hash,
                    "model": self.model,
                    "schema_version": SCHEMA_VERSION,
                    "prompt_version": PROMPT_VERSION,
                    "gates_version": GATES_VERSION,
                    "feedback_digest": self.feedback_digest,
                },
                sort_keys=True,
            )
        )


class AgenticScanCache:
    def __init__(self, repository_path: Path) -> None:
        self.root = repository_path / ".difend" / "cache"

    def get(self, key: CacheKey) -> AgenticScanResult | None:
        path = self._path(key)
        if not path.exists():
            return None
        try:
            return AgenticScanResult.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def set(self, key: CacheKey, result: AgenticScanResult) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self._path(key).write_text(
            result.model_dump_json(indent=2) + "\n",
            encoding="utf-8",
        )

    def _path(self, key: CacheKey) -> Path:
        return self.root / f"{key.digest()}.json"


def context_hash(value: Any) -> str:
    return stable_hash(json.dumps(value, sort_keys=True, default=str))
