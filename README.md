# Difend - Diff Defend

## Idea

### Pain Point

AI-assisted coding lets developers and Codex produce code changes quickly, but security review often becomes the bottleneck. A single diff can include hidden risks that are easy to miss during normal code review, especially when reviewers are also checking functionality, style, and correctness.

Automated security tools are useful for common issues like leaked secrets, vulnerable dependencies, injection patterns, and unsafe cryptography. However, they are weaker at detecting deeper security risks in authentication, authorisation, privilege boundaries, business logic, and sensitive data flows.

Teams need a lightweight workflow that checks only the code diff, catches common vulnerabilities automatically, and flags suspicious changes for human security review when deeper context is required. They also need a way to preserve that review context so a developer can continue the task with Codex or another AI coding assistant without re-explaining what changed, what was scanned, and what still needs attention.

Difend is designed as a diff-aware AI security review SDK with a CLI entry point. The CLI gives developers quick terminal feedback, while the SDK coordinates focused review agents and produces a persistent scan bundle that can be read by developers, security reviewers, Codex, or another AI coding assistant.

The scan bundle is not only a security report. It is structured context for follow-up work. After an AI coding tool generates a code change, `difend scan` turns the current Git diff into Markdown and JSON files that explain what changed, which agents reviewed it, what problems were found, what needs manual review, and which files Codex should inspect next.

### Product Shape

Difend has three connected layers:

- **CLI:** `difend scan` gives the developer immediate terminal feedback after a code change.
- **SDK:** the reusable scan engine captures diffs, coordinates review agents, creates findings, and writes scan bundles.
- **Context bundle:** the generated `.md`, `.patch`, and `.json` files give Codex or another AI coding tool focused security context for deeper review, explanation, or remediation.

This means Difend supports two workflows at the same time: quick local security feedback for the developer, and better context awareness for AI coding tools that continue the task.

## AI Agent System

Difend is agent-based because the scan is split into focused review roles. Each agent receives the current diff, makes a bounded security judgement, and returns structured output that the SDK merges into the final report.

The first version of Difend should use three agents:

- **Automated Gates Agent:** checks the diff for concrete security problems such as hardcoded secrets, dangerous dependency changes, injection patterns, unsafe shell execution, weak cryptography, and sensitive data exposure.
- **Security Review Agent:** looks for suspicious changes that may require deeper judgement, especially authentication, authorisation, privilege boundaries, sessions, personal data, database access, file access, payments, and cryptography.
- **Handoff Agent:** turns the scan result into clear follow-up context for Codex or another AI coding assistant, including what was scanned, what was found, which files to inspect next, and the safest next action.

The SDK acts as the coordinator. It captures the diff, runs the agents, combines their outputs, decides the final status, and writes the scan bundle.

Agent outputs should be structured so they can be written to both Markdown and JSON:

- `findings`: concrete security issues found by the Automated Gates Agent.
- `manual_review`: uncertain or context-dependent risks found by the Security Review Agent.
- `codex_instructions`: follow-up instructions produced by the Handoff Agent.
- `status`: final result of `pass`, `fail`, or `manual review required`.

## Workflow

Difend focuses only on the code diff. It does not try to review the whole repository unless the changed lines require related context.

### Execution Flow

1. Developer or Codex makes changes to the repository.
2. Developer runs:

```bash
difend scan
```

3. The command triggers the `difend SDK`.
4. The `difend SDK` captures the current code diff from the Git working tree.
5. Difend creates a scan output folder for the current run.
6. The SDK sends the diff into three focused agent review directions:

- **Automated Gates Agent:** detects common vulnerabilities in the diff, such as leaked secrets, vulnerable dependencies, injection risks, unsafe auth changes, weak cryptography, and sensitive data exposure. This should handle around 80% of routine security detection.
- **Security Review Agent:** looks for suspicious code that may contain deeper flaws. The agent starts from the diff, traces related files only when needed, and asks for manual review when the code may affect authentication, authorisation, privilege boundaries, secrets, personal data, database queries, file access, payments, cryptography, or session management. This should handle around 20% of cases where human verification is required.
- **Handoff Agent:** prepares the Codex follow-up instructions so the developer can continue safely without re-explaining the scan context.

7. Difend prints progress in the terminal while each check runs.
8. Difend waits for the agents to finish.
9. Difend combines the agent results into one final security report and context handoff.
10. Difend writes the final output into the scan folder as Markdown files, the exact scanned patch, and machine-readable JSON.
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
Running Automated Gates Agent... done
Running Security Review Agent... manual review required
Running Handoff Agent... done

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

The final scan bundle should include:

- Automated Gates Agent findings
- Security Review Agent risks that require human verification
- Files and lines involved
- Recommended fixes
- Manual review checklist
- Handoff Agent Codex follow-up instructions
- The exact diff that was scanned
- Final status: pass, fail, or manual review required

Suggested file responsibilities:

- `summary.md`: human-readable scan summary, final status, checks performed, and next steps.
- `findings.md`: concrete automated gate findings with severity, evidence, location, and recommendation.
- `manual-review.md`: suspicious areas that require human or AI-assisted security judgment.
- `codex-instructions.md`: a focused prompt-style handoff file that tells Codex what was scanned, what needs deeper review, which files to inspect, and how to continue the developer's task safely.
- `diff.patch`: the exact Git diff that Difend scanned.
- `report.json`: structured machine-readable report for future integrations, CI, IDE plugins, and AI coding tools.

### Context Handoff Contract

Every scan should leave enough context for a future reviewer or AI coding assistant to answer these questions without starting from scratch:

- What diff was scanned?
- Which files and added lines were involved?
- Which agents ran?
- Which findings are concrete security problems?
- Which areas are suspicious but need deeper judgement?
- What should Codex inspect next?
- What is the safest next action for the developer?

Core principle: review the diff first, trace context only when needed, and escalate uncertain security risks to a human or AI-assisted follow-up review with clear evidence.

## Roadmap

### 28/04/2026
- Agreement on final idea.
- Find resources for implementation.

### 29/04/2026
- Implement the first version of the `difend scan` command.
- Implement code diff capture from the current Git working tree.
- Define the core `difend SDK` interface:
  - input: repository path and diff
  - output: structured security report, final status, and scan output folder
- Create `.difend/runs/<run-id>/` for each scan.
- Write the first scan bundle files:
  - `summary.md`
  - `findings.md`
  - `manual-review.md`
  - `codex-instructions.md`
  - `diff.patch`
  - `report.json`
- Build the first agent runner.
- Add initial Automated Gates Agent checks:
  - secrets scanning
  - dependency change detection
  - simple injection pattern checks
  - risky authentication or authorisation change detection
- Define a shared finding format with file, line, severity, evidence, gate name, and recommendation.
- Combine agent results into one partial report.
- Print progress for each check in the terminal.
- Make `codex-instructions.md` useful as a direct handoff prompt for Codex.
- Test the command against small sample diffs.

Goal for the day: `difend scan` can capture a diff, run basic review agents, print terminal progress, and write a structured scan bundle to `.difend/runs/<run-id>/` that developers can hand to Codex for follow-up.

### 30/04/2026
- Implement the Security Review Agent.
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
