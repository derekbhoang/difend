import subprocess


def run_git_command(args):
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

    return result.stdout


def capture_unstaged_diff():
    return run_git_command(["diff", "--no-ext-diff", "--unified=0"])


def capture_staged_diff():
    return run_git_command(["diff", "--cached", "--no-ext-diff", "--unified=0"])


def capture_code_diff():
    return {
        "unstaged": capture_unstaged_diff(),
        "staged": capture_staged_diff(),
    }


def main():
    diff = capture_code_diff()

    print("=== Unstaged diff ===")
    print(diff["unstaged"] or "No unstaged changes.")

    print("=== Staged diff ===")
    print(diff["staged"] or "No staged changes.")


if __name__ == "__main__":
    main()
