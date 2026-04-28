# Difend - Diff Defend

## Idea

### Pain Point

AI-assisted coding lets developers and Codex produce code changes quickly, but security review often becomes the bottleneck. A single diff can include hidden risks that are easy to miss during normal code review, especially when reviewers are also checking functionality, style, and correctness.

Automated security tools are useful for common issues like leaked secrets, vulnerable dependencies, injection patterns, and unsafe cryptography. However, they are weaker at detecting deeper security risks in authentication, authorisation, privilege boundaries, business logic, and sensitive data flows.

Teams need a lightweight workflow that checks only the code diff, catches common vulnerabilities automatically, and flags suspicious changes for human security review when deeper context is required.

Difend is designed as a security review SDK with a CLI entry point. The CLI gives developers quick terminal feedback, while the SDK produces a persistent review bundle that can be read by developers, security reviewers, Codex, or another AI coding assistant.

## Workflow

Difend focuses only on the code diff. It does not try to review the whole repository unless the changed lines require related context.

### Execution Flow

1. Developer or Codex makes changes to the repository.
2. Developer runs:

```bash
difend scan
```

3. The command triggers the `difend SDK`.
4. The `difend SDK` captures the current code diff from the Git working tree, including staged changes, unstaged changes, and Git-reported untracked text files.
5. Difend creates a scan output folder for the current run.
6. The SDK sends the diff into two asynchronous security review directions:

- **Automated gates:** Detect common vulnerabilities in the diff, such as leaked secrets, vulnerable dependencies, injection risks, unsafe auth changes, weak cryptography, and sensitive data exposure. This should handle around 80% of routine security detection.
- **Security risks:** Look for suspicious code that may contain deeper flaws. The SDK starts from the diff, traces related files only when needed, and asks for manual review when the code may affect authentication, authorisation, privilege boundaries, secrets, personal data, database queries, file access, payments, cryptography, or session management. This should handle around 20% of cases where human verification is required.

7. Difend prints progress in the terminal while each check runs.
8. Difend waits for both directions to finish.
9. Difend combines the results into one final security report.
10. Difend writes the final report into the scan output folder as Markdown files and machine-readable JSON.
11. The developer can continue in Codex by asking it to read the generated Markdown files for deeper review, explanation, or remediation.
12. The final status is one of:

- `pass`
- `fail`
- `manual review required`

### Terminal Experience

The terminal output should be short, readable, and useful during normal development.

Example:

```text
Difend scan started

Checking git diff... done
Checking secrets... done
Checking dependency changes... done
Checking injection risks... warning
Checking auth and permission changes... manual review required

Status: manual review required
Report written to: .difend/runs/2026-04-29-001/
Next: ask Codex to read .difend/runs/2026-04-29-001/codex-instructions.md
```

### Final Output

Each scan should always generate an output folder, even when no problems are found.

Example:

```text
.difend/
  runs/
    2026-04-29-001/
      summary.md
      findings.md
      manual-review.md
      codex-instructions.md
      diff.patch
      report.json
```

The final report should include:

- Automated gate findings
- Security risks that require human verification
- Files and lines involved
- Recommended fixes
- Manual review checklist
- Final status: pass, fail, or manual review required

Suggested file responsibilities:

- `summary.md`: human-readable scan summary, final status, and next steps.
- `findings.md`: concrete automated gate findings with severity, evidence, location, and recommendation.
- `manual-review.md`: suspicious areas that require human or AI-assisted security judgment.
- `codex-instructions.md`: a focused prompt-style handoff file that tells Codex what was scanned, what needs deeper review, and which files to inspect.
- `diff.patch`: the exact Git diff that Difend scanned.
- `report.json`: structured machine-readable report for future integrations.

Core principle: review the diff first, trace context only when needed, and escalate uncertain security risks to a human.

## Local Development

Install Difend in editable mode:

```bash
pip install -e .
```

Run a scan from inside a Git repository:

```bash
difend scan
```

Run the test suite:

```bash
python -m unittest discover
```

## Roadmap

### 28/04/2026
- Agreement on final idea.
- Find resources for implementation.

### 29/04/2026
- Implement the first version of the `difend scan` command.
- Implement code diff capture from the current Git working tree.
- Define the core `difend SDK` interface:
  - input: repository path and diff
  - output: structured security report and scan output folder
- Create `.difend/runs/<run-id>/` for each scan.
- Write the first scan bundle files:
  - `summary.md`
  - `findings.md`
  - `codex-instructions.md`
  - `diff.patch`
  - `report.json`
- Build the automated gates runner.
- Add initial automated gates:
  - secrets scanning
  - dependency change detection
  - simple injection pattern checks
  - risky authentication or authorisation change detection
- Define a shared finding format with file, line, severity, evidence, gate name, and recommendation.
- Combine automated gate results into one partial report.
- Print progress for each check in the terminal.
- Test the command against small sample diffs.

Goal for the day: `difend scan` can capture a diff, run basic automated gates, print terminal progress, and write a structured scan bundle to `.difend/runs/<run-id>/`.

### 30/04/2026
- Implement the security risk review direction.
- Detect when changed code may require human verification, especially changes involving:
  - authentication
  - authorisation
  - privilege boundaries
  - secrets
  - sensitive data
  - database queries
  - file access
  - payments
  - cryptography
  - session management
- Add related-file tracing from the diff:
  - called functions
  - imported modules
  - route handlers
  - auth helpers
  - data models
  - related tests
- Generate a manual review checklist when suspicious security risk is found.
- Merge automated gate findings and security risk findings into one final report.
- Write `manual-review.md` for suspicious changes that need deeper review.
- Improve `codex-instructions.md` so developers can ask Codex to read the scan bundle and continue the security review.
- Implement final statuses:
  - `pass`
  - `fail`
  - `manual review required`
- Polish CLI output for developer readability.
- Run end-to-end tests on sample vulnerable diffs.
- Document known limitations and next steps.

Goal for the day: Difend can run the full two-direction workflow and produce a final diff-only security review report with Markdown files that support Codex-assisted follow-up.

## Resources
- [**Resource 1:** AI-Generated Code Security Risks - Why Vulnerabilities Increase 2.74x and How to Prevent Them](https://www.softwareseni.com/ai-generated-code-security-risks-why-vulnerabilities-increase-2-74x-and-how-to-prevent-them/)
