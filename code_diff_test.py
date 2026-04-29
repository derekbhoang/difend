from pathlib import Path

from difend.cli import main


if __name__ == "__main__":
    repo_path = Path(__file__).resolve().parent
    raise SystemExit(main(["scan", "--repo", str(repo_path)]))
