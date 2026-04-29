from pathlib import Path

from difend.cli import main


if __name__ == "__main__":
    raise SystemExit(main(default_repo_path=Path(__file__).resolve().parent))
