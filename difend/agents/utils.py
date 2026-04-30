"""Small deterministic helpers for agent outputs."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


def stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def stable_short_hash(value: str, length: int = 12) -> str:
    return stable_hash(value)[:length]


def evidence_fingerprint(
    file: str,
    line: int | None,
    vulnerability_type: str,
    evidence: str,
) -> str:
    return stable_short_hash(
        json.dumps(
            {
                "file": normalize_path(file),
                "line": line,
                "type": vulnerability_type.strip().lower(),
                "evidence": evidence.strip(),
            },
            sort_keys=True,
        )
    )


def normalize_path(path: str | Path) -> str:
    return str(path).replace("\\", "/").lstrip("./")


def compact_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def model_dump(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "dict"):
        return value.dict()
    raise TypeError(f"Cannot dump object of type {type(value)!r}")
