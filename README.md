# Difend - Diff Defend

## Idea

### Pain Point

AI-assisted coding lets developers and Codex produce code changes quickly, but security review often becomes the bottleneck. A single diff can include hidden risks that are easy to miss during normal code review, especially when reviewers are also checking functionality, style, and correctness.

Automated security tools are useful for common issues like leaked secrets, vulnerable dependencies, injection patterns, and unsafe cryptography. However, they are weaker at detecting deeper security risks in authentication, authorisation, privilege boundaries, business logic, and sensitive data flows.

Teams need a lightweight workflow that checks only the code diff, catches common vulnerabilities automatically, and flags suspicious changes for human security review when deeper context is required. They also need a way to preserve that review context so a developer can continue the task with Codex or another AI coding assistant without re-explaining what changed, what was scanned, and what still needs attention.

Difend is designed as a diff-aware security review SDK with a CLI entry point. The CLI gives developers quick terminal feedback, while the SDK produces a persistent scan bundle that can be read by developers, security reviewers, Codex, or another AI coding assistant.

The scan bundle is not only a security report. It is structured context for follow-up work. After an AI coding tool generates a code change, `difend scan` turns the current Git diff into Markdown and JSON files that explain what changed, which security checks ran, what problems were found, what needs manual review, and which files Codex should inspect next.

### Product Shape

Difend has three connected layers:

- **CLI:** `difend scan` gives the developer immediate terminal feedback after a code change.
- **SDK:** the reusable scan engine captures diffs, runs gates, creates findings, and writes scan bundles.
- **Context bundle:** the generated `.md`, `.patch`, and `.json` files give Codex or another AI coding tool focused security context for deeper review, explanation, or remediation.

This means Difend supports two workflows at the same time: quick local security feedback for the developer, and better context awareness for AI coding tools that continue the task.

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
6. The SDK sends the diff into two asynchronous security review directions:

- **Automated gates:** Detect common vulnerabilities in the diff, such as leaked secrets, vulnerable dependencies, injection risks, unsafe auth changes, weak cryptography, and sensitive data exposure. This should handle around 80% of routine security detection.
- **Security risks:** Look for suspicious code that may contain deeper flaws. The SDK starts from the diff, traces related files only when needed, and asks for manual review when the code may affect authentication, authorisation, privilege boundaries, secrets, personal data, database queries, file access, payments, cryptography, or session management. This should handle around 20% of cases where human verification is required.

7. Difend prints progress in the terminal while each check runs.
8. Difend waits for both directions to finish.
9. Difend combines the results into one final security report and context handoff.
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
      context-signals.md
      findings.md
      manual-review.md
      solution-proposals.md
      codex-instructions.md
      diff.patch
      report.json
```

The final scan bundle should include:

- Rule-based automated gate signals
- Agent-confirmed findings, when a later review step has produced them
- Security risks that require human verification
- Files and lines involved
- Recommended fixes or solution proposals
- Manual review checklist
- Codex follow-up instructions
- The exact diff that was scanned
- Final status: pass, fail, or manual review required

Suggested file responsibilities:

- `summary.md`: human-readable scan summary, final status, checks performed, and next steps.
- `context-signals.md`: rule-based automated gate signals collected as context for Codex or another review agent.
- `findings.md`: agent-confirmed findings with severity, evidence, location, agent name, and recommendation. Automated gates should not write final confirmed findings directly.
- `manual-review.md`: suspicious areas that require human or AI-assisted security judgment.
- `solution-proposals.md`: non-mutating proposed fixes, implementation notes, suggested tests, and caveats for developers and Codex.
- `codex-instructions.md`: a focused prompt-style handoff file that tells Codex what was scanned, what needs deeper review, which files to inspect, and how to continue the developer's task safely.
- `diff.patch`: the exact Git diff that Difend scanned.
- `report.json`: structured machine-readable report for future integrations, CI, IDE plugins, dashboards, Codex, and downstream AI agents. Automated gates write `rule_signals` here; later LLM or agent review can use those signals to produce `findings.md`.

The first implementation separates the workflow into two commands:

- `difend scan`: captures the Git diff, runs rule-based automated gates, and writes `report.json` plus context files.
- `difend review`: calls the Codex agent layer through the OpenAI Responses API, reads `report.json` and `diff.patch`, then writes agent-confirmed `findings.md` and `solution-proposals.md`.

### Context Handoff Contract

Every scan should leave enough context for a future reviewer or AI coding assistant to answer these questions without starting from scratch:

- What diff was scanned?
- Which files and added lines were involved?
- Which automated checks ran?
- Which findings are concrete security problems?
- Which areas are suspicious but need deeper judgement?
- What should Codex inspect next?
- What is the safest next action for the developer?

Core principle: review the diff first, trace context only when needed, and escalate uncertain security risks to a human or AI-assisted follow-up review with clear evidence.

## Testing the Automated Gates Flow

This section shows the simplest end-to-end demo for the current automated gates implementation on the `testting-gates` branch.

There are two different repositories involved in the demo:

- **Difend source repository:** the repository containing this README and the `difend` Python package.
- **Demo target repository:** a temporary Git repository that contains a small code change for Difend to scan.

Do not run the demo commands from inside a `.git` directory. Run them from the root of the demo target repository.

### 1. Check Out This Branch

```bash
git clone -b testting-gates https://github.com/derekbhoang/difend.git
cd difend
```

If you already have the repository locally:

```bash
git fetch origin
git switch testting-gates
```

### 2. Run the Unit Tests

From the Difend source repository:

```bash
python3 -m unittest discover
```

Expected result:

```text
Ran 11 tests
OK
```

### 3. Create a Clean Demo Repository

Keep the Difend source path in an environment variable, then create a temporary Git repository to scan:

```bash
export DIFEND_SRC="$(pwd)"
DEMO=$(mktemp -d /tmp/difend-demo.XXXXXX)

cd "$DEMO"
git init

printf '# Difend demo\n' > README.md
printf '.difend/\n' > .gitignore

git add README.md .gitignore
git -c user.name=Demo -c user.email=demo@example.com commit -m init
```

The `.gitignore` entry is important because Difend writes scan output to `.difend/`. Ignoring that folder prevents later scans from scanning previous scan reports.

Confirm that you are in the demo repository root:

```bash
pwd
git status --short
```

The path should look like `/tmp/difend-demo.xxxxxx`, not `/tmp/difend-demo.xxxxxx/.git`.

### 4. Add a Risky Code Change

Create a new file with an intentionally unsafe `eval` call:

```bash
cat > risky_app.py <<'PY'
def run_user_code(user_input):
    return eval(user_input)
PY
```

Confirm Git sees the new file:

```bash
git status --short
```

Expected result:

```text
?? risky_app.py
```

### 5. Run Difend Scan

Run Difend from the demo repository, using `PYTHONPATH` to point Python at the Difend source repository:

```bash
PYTHONPATH="$DIFEND_SRC" python3 -m difend scan
```

Expected terminal output includes:

```text
Difend scan started

Checking git diff... done
Checking secrets... done
Checking dependency changes... done
Checking injection risks... warning
Checking auth and permission changes... done

Status: manual review required
Report written to: .difend/runs/<run-id>
Next: ask Codex to read .difend/runs/<run-id>/codex-instructions.md
```

The status is `manual review required` because the injection gate produced a rule signal for `eval(user_input)`.

### 6. Read the Scan Bundle

Find the latest scan folder:

```bash
RUN=$(ls -td .difend/runs/* | head -1)
```

Read the human summary:

```bash
cat "$RUN/summary.md"
```

Read the rule-based context signals:

```bash
cat "$RUN/context-signals.md"
```

Expected signal:

```text
risky_app.py:2
Gate: injection risks
Severity: high
Evidence: return eval(user_input)
```

Read the machine-readable report that Codex or a downstream agent should use as its main input:

```bash
cat "$RUN/report.json"
```

In the JSON, automated gates write to `rule_signals`. The `findings` array is reserved for later LLM or agent-confirmed findings.

Read the current findings file:

```bash
cat "$RUN/findings.md"
```

Expected result before the LLM or agent review step:

```text
No agent-confirmed findings have been generated yet.
```

Read the Codex handoff prompt:

```bash
cat "$RUN/codex-instructions.md"
```

That file is meant to be handed to Codex or another reviewer so they can read `report.json`, inspect the exact diff, validate the rule signals, and produce confirmed findings or solution proposals.

### 7. Run the Codex Agent Review

The scan step does not call an LLM. It only writes rule-based context into `report.json`.

To ask the Codex agent layer to confirm findings, set `OPENAI_API_KEY` and run:

```bash
export OPENAI_API_KEY="your-api-key"
PYTHONPATH="$DIFEND_SRC" python3 -m difend review "$RUN"
```

By default, the agent client uses `gpt-5.1-codex` through the OpenAI Responses API. You can override the model with:

```bash
PYTHONPATH="$DIFEND_SRC" python3 -m difend review "$RUN" --model gpt-5.1-codex
```

Expected terminal output includes:

```text
Difend agent review started

Status: manual review required
Findings written to: .difend/runs/<run-id>/findings.md
Solution proposals written to: .difend/runs/<run-id>/solution-proposals.md
Report updated: .difend/runs/<run-id>/report.json
```

After the review step, read the agent-confirmed findings and proposed fixes:

```bash
cat "$RUN/findings.md"
cat "$RUN/solution-proposals.md"
cat "$RUN/report.json"
```

The agent should use `report.json.rule_signals` and `diff.patch` as context, then write confirmed issues into `findings.md` and non-mutating fix ideas into `solution-proposals.md`.

### 8. Fix the Risky Code

Replace the unsafe `eval` call with a harmless return for this demo:

```bash
cat > risky_app.py <<'PY'
def run_user_code(user_input):
    return user_input
PY
```

### 9. Scan Again

```bash
PYTHONPATH="$DIFEND_SRC" python3 -m difend scan
```

Expected result:

```text
Checking injection risks... done
Status: pass
```

Open the latest context signals and findings reports:

```bash
RUN=$(ls -td .difend/runs/* | head -1)
cat "$RUN/context-signals.md"
cat "$RUN/findings.md"
```

Expected result:

```text
No rule-based context signals were detected.
No agent-confirmed findings have been generated yet.
```

### 10. Clean Up the Demo Repository

When you are finished:

```bash
cd /tmp
rm -rf "$DEMO"
```

### Demo Flow Summary

```text
1. Create a clean demo Git repository.
2. Add a risky file containing eval(user_input).
3. Run difend scan.
4. Difend captures the Git diff and scans only added lines.
5. The injection gate writes a high-risk rule signal into report.json.
6. Read summary.md, context-signals.md, report.json, and codex-instructions.md.
7. Run difend review to call the Codex agent and produce findings.md.
8. Fix the risky code.
9. Run difend scan again.
10. The scan passes when no rule-based context signals remain.
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
  - output: structured security report, final status, and scan output folder
- Create `.difend/runs/<run-id>/` for each scan.
- Write the first scan bundle files:
  - `summary.md`
  - `findings.md`
  - `manual-review.md`
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
- Make `codex-instructions.md` useful as a direct handoff prompt for Codex.
- Test the command against small sample diffs.

Goal for the day: `difend scan` can capture a diff, run basic automated gates, print terminal progress, and write a structured scan bundle to `.difend/runs/<run-id>/` that developers can hand to Codex for follow-up.

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
