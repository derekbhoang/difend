"""Configuration helpers for Difend."""

from __future__ import annotations

from pathlib import Path


def load_environment(repository_path: str | Path = ".") -> None:
    """Load local .env values without overriding existing environment variables."""

    try:
        from dotenv import load_dotenv
    except ImportError:
        return

    path = Path(repository_path) / ".env"
    if path.exists():
        load_dotenv(path, override=False)
