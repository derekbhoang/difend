import datetime as dt
from pathlib import Path


def runs_root(repo_path):
    return Path(repo_path) / ".difend" / "runs"


def next_run_id(root):
    today = dt.date.today().isoformat()
    root.mkdir(parents=True, exist_ok=True)

    highest = 0
    for path in root.iterdir():
        if not path.is_dir() or not path.name.startswith(f"{today}-"):
            continue

        suffix = path.name.removeprefix(f"{today}-")
        if suffix.isdigit():
            highest = max(highest, int(suffix))

    return f"{today}-{highest + 1:03d}"


def create_scan_output_folder(repo_path):
    root = runs_root(repo_path)
    output_folder = root / next_run_id(root)
    output_folder.mkdir(parents=True, exist_ok=False)
    return output_folder


def save_raw_diff(raw_diff, output_folder):
    diff_path = Path(output_folder) / "diff.patch"
    diff_path.write_text(raw_diff, encoding="utf-8")
    return diff_path
