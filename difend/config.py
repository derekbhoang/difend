"""Configuration helpers for Difend."""

from __future__ import annotations

from pathlib import Path


def load_environment(repository_path: str | Path = ".") -> None:
    """Load local .env values without overriding existing environment variables."""

    try:
        from dotenv import load_dotenv
    except ImportError:
        return

    repo_path = Path(repository_path)
    candidates = [
        repo_path / ".env",
        Path.cwd() / ".env",
    ]
    for path in candidates:
        if path.exists():
            load_dotenv(path, override=False)
