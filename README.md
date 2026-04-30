# Difend - Diff Defend

## Idea

### Pain Point

AI-assisted coding lets developers and Codex produce code changes quickly, but security review often becomes the bottleneck. A single diff can include hidden risks that are easy to miss during normal code review, especially when reviewers are also checking functionality, style, and correctness.

Automated security tools are useful for common issues like leaked secrets, vulnerable dependencies, injection patterns, and unsafe cryptography. However, they are weaker at detecting deeper security risks in authentication, authorisation, privilege boundaries, business logic, and sensitive data flows.

Teams need a lightweight workflow that checks only the code diff, catches common vulnerabilities automatically, and flags suspicious changes for human security review when deeper context is required. They also need a way to preserve that review context so a developer can continue the task with Codex or another AI coding assistant without re-explaining what changed, what was scanned, and what still needs attention.

Difend is designed as a diff-aware AI security review SDK with a CLI entry point. The CLI gives developers quick terminal feedback, while the SDK coordinates focused review agents and produces a persistent scan bundle that can be read by developers, security reviewers, Codex, or another AI coding assistant.

The scan bundle is not only a security report. It is structured context for follow-up work. After an AI coding tool generates a code change, `difend scan` or `difend agent-scan` turns the current Git diff into Markdown and JSON files that explain what changed, which checks reviewed it, what problems were found, what needs manual review, and which files Codex should inspect next. Each run also writes a structured `scan-log.jsonl` event timeline for observability.

### Product Shape

Difend has three connected layers:

- **CLI:** `difend scan` gives fast deterministic Automated Gates feedback, while `difend agent-scan` runs the full agentic workflow.
- **SDK:** the reusable scan engine captures diffs, coordinates review agents, creates findings, emits progress events, and writes scan bundles.
- **Context bundle:** the generated `.md`, `.patch`, and `.json` files give Codex or another AI coding tool focused security context for deeper review, explanation, or remediation.

This means Difend supports two workflows at the same time: quick local security feedback for the developer, and better context awareness for AI coding tools that continue the task.

## AI Agent System

Difend is agent-based because the scan is split into focused review roles. Each agent receives bounded scan context, makes a bounded security judgement, and returns structured output that the SDK merges into the final report.

The implementation uses a coordinator-led agentic architecture:

```text
prepare_scan_context
  |
  v
diff_classifier (heuristic -> optional LLM)
  |
  v
orchestrator_route
  |-- automated_gates
  |     `-- optional LLM validation
  |
  |-- context_expansion (bounded + security-aware)
  |
  |-- security_reasoning (conditional)
  |
  v
orchestrator_merge
  - dedupe with enhanced key
  - enforce Automated Gates priority
  - remove overlap
  |
  v
handoff (no new findings)
  |
  v
orchestrator_finalize
```

The Agent Orchestrator is deterministic LangGraph control flow. It routes work, merges output, applies cache/feedback, removes duplicates, and decides final status. It does not perform deep security review.

Difend uses four specialist agents:

- **Diff Classifier Agent:** classifies changed files and added lines into fixed risk areas. It uses heuristics first and only calls the LLM when a diff is not confidently low risk.
- **Automated Gates Agent:** checks the diff for concrete security problems such as hardcoded secrets, dangerous dependency changes, injection patterns, unsafe shell execution, unsafe deserialization, weak cryptography, plaintext password handling, insecure debug/config settings, path traversal, open redirects, permissive CORS, insecure cookies, and sensitive data exposure.
- **Security Reasoning Agent:** looks for suspicious changes that may require deeper judgement, especially authentication, authorisation, privilege boundaries, sessions, personal data, database access, file access, payments, and cryptography. It outputs manual review items only.
- **Handoff Agent:** turns the merged scan result into clear follow-up context for Codex or another AI coding assistant, including what was scanned, what was found, which files to inspect next, and the safest next action. It does not introduce new findings.

The SDK acts as the coordinator. It captures the diff, runs the agents, combines their outputs, decides the final status, and writes the scan bundle.

Agent outputs should be structured so they can be written to both Markdown and JSON:

- `risk_areas`: risk categories found by the Diff Classifier Agent.
- `findings`: concrete security issues found by the Automated Gates Agent.
- `manual_review`: uncertain or context-dependent risks found by the Security Reasoning Agent.
- `codex_instructions`: follow-up instructions produced by the Handoff Agent.
- `status`: final result of `pass`, `fail`, or `manual review required`.

The final status is deterministic:

- Any active Automated Gates finding produces `fail`.
- If there are no active findings but there are manual review items, status is `manual review required`.
- If neither exists, status is `pass`.

Configuration:

- `OPENAI_API_KEY` is never required for `difend scan`; it is required only when `difend agent-scan` needs an LLM-backed agent.
- `DIFEND_OPENAI_MODEL` optionally overrides the default model, `gpt-5.4-mini`.
- LangSmith tracing is optional and follows the standard LangChain environment variables when configured.

## Workflow

Difend focuses only on the code diff. It does not try to review the whole repository unless the changed lines require related context.

### Execution Flow

1. Developer or Codex makes changes to the repository.
2. Developer runs:

```bash
difend scan
```

For the full agentic workflow, run:

```bash
difend agent-scan
```

Useful `agent-scan` flags:

```bash
difend agent-scan --no-cache
difend agent-scan --model gpt-5.4-mini
difend agent-scan --strict
difend agent-scan --agents
```

3. The command triggers the `difend SDK`.
4. The `difend SDK` captures the current code diff from the Git working tree.
5. Difend creates a scan output folder for the current run.
6. For `difend scan`, the SDK runs deterministic Automated Gates only. For `difend agent-scan`, the SDK sends the diff through the LangGraph agentic workflow:

- **Diff Classifier Agent:** classifies the diff into fixed risk areas using heuristics first and optional LLM structured output.
- **Automated Gates Agent:** detects concrete vulnerabilities in the diff, such as leaked secrets, vulnerable dependencies, injection risks, unsafe auth changes, plaintext password handling, unsafe deserialization, path traversal, weak cryptography, and sensitive data exposure.
- **Security Reasoning Agent:** conditionally analyzes deeper contextual risk and outputs manual-review items only.
- **Handoff Agent:** prepares the Codex follow-up instructions so the developer can continue safely without re-explaining the scan context.

7. Difend prints a percentage progress bar in the terminal while each check runs.
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

Agentic example:

```text
Difend agent-scan started

[----------------] 0% scan started - Difend agent-scan started.
[#---------------] 8% diff_capture completed - Captured unstaged diff.
[###-------------] 17% prepare_scan_context completed - Prepared 1 changed file(s).
[####------------] 25% diff_classifier completed - Classified diff with LLM structured output.
[#####-----------] 33% orchestrator_route completed - Automated Gates will run; Security Reasoning is conditional.
[#######---------] 42% context_expansion completed - Expanded 1 context file(s).
[########--------] 50% cache_lookup completed - Cache miss.
[#########-------] 58% automated_gates completed - Detected 1 concrete finding(s).
[###########-----] 67% security_reasoning completed - Produced 1 manual review item(s).
[############----] 75% orchestrator_merge completed - Merged outputs, enforced priority, and removed overlap.
[#############---] 83% handoff completed - Generated handoff from merged scan result.
[###############-] 92% orchestrator_finalize completed - Final status: manual review required.
[################] 100% bundle_write completed - Wrote scan bundle to .difend/runs/2026-04-29-001.

Status: manual review required
Report written to: .difend/runs/2026-04-29-001/
Log written to: .difend/runs/2026-04-29-001/scan-log.jsonl
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
      agent-trace.json
      scan-log.jsonl
```

The final scan bundle should include:

- Automated Gates Agent findings
- Security Reasoning Agent risks that require human verification
- Files and lines involved
- Recommended fixes
- Manual review checklist
- Handoff Agent Codex follow-up instructions
- The exact diff that was scanned
- A structured JSONL event log for scan and agent observability
- Final status: pass, fail, or manual review required

Suggested file responsibilities:

- `summary.md`: human-readable scan summary, final status, checks performed, and next steps.
- `findings.md`: concrete automated gate findings with severity, evidence, location, and recommendation.
- `manual-review.md`: suspicious areas that require human or AI-assisted security judgment.
- `codex-instructions.md`: a focused prompt-style handoff file that tells Codex what was scanned, what needs deeper review, which files to inspect, and how to continue the developer's task safely.
- `diff.patch`: the exact Git diff that Difend scanned.
- `report.json`: structured machine-readable report for future integrations, CI, IDE plugins, and AI coding tools.
- `agent-trace.json`: raw/intermediate scan trace for debugging agent and gate behavior.
- `scan-log.jsonl`: timestamped scan events with phase status, progress percentage, duration, LLM usage, and metadata.

### Context Handoff Contract

Every scan should leave enough context for a future reviewer or AI coding assistant to answer these questions without starting from scratch:

- What diff was scanned?
- Which files and added lines were involved?
- Which agents ran?
- Which findings are concrete security problems?
- Which areas are suspicious but need deeper judgement?
- What should Codex inspect next?
- What is the safest next action for the developer?

Core principle: review the diff first, expand only bounded security-aware context when needed, and escalate uncertain security risks to a human or AI-assisted follow-up review with clear evidence.

## Development Setup

Create and activate a virtual environment:

```bash
python -m venv .venv
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the package and test dependencies:

```bash
python -m pip install -r requirements-dev.txt
python -m pip install -e .
```

Configure OpenAI when model-backed nodes are needed:

```bash
OPENAI_API_KEY=...
DIFEND_OPENAI_MODEL=gpt-5.4-mini
```

You can also put these values in a local `.env` file at the repository root:

```text
OPENAI_API_KEY=your_api_key_here
DIFEND_OPENAI_MODEL=gpt-5.4-mini
```

`.env` is ignored by Git. Keep `.env.example` committed as the safe template.

Run tests:

```bash
python -m pytest
```

## Package And Publish

Difend is packaged as both a Python SDK and a CLI. Installing the package exposes
the `difend` command and the public SDK imports:

```python
from difend import DifendSDK, ScanRequest, agent_scan, scan
```

Validate the package locally before publishing:

```powershell
python -m pip install -r requirements-dev.txt
python -m pip install -e .
python -m pytest
python -m compileall difend
python -m build
python -m twine check dist/*
```

Publish to TestPyPI first:

```powershell
$env:TWINE_USERNAME="__token__"
$env:TWINE_PASSWORD=(Read-Host "TestPyPI API token")
python -m twine upload --repository testpypi dist/*
```

Then verify installation from TestPyPI in a clean virtual environment:

```powershell
python -m venv .venv-testpkg
.\.venv-testpkg\Scripts\Activate.ps1
$testPypi = "https://test.pypi.org/simple/"
$pypi = "https://pypi.org/simple/"
python -m pip install --index-url $testPypi --extra-index-url $pypi difend==0.1.0
difend scan
python -c "from difend import scan, agent_scan, DifendSDK; print('ok')"
deactivate
```

Publish to real PyPI only after TestPyPI installation works:

```powershell
$env:TWINE_USERNAME="__token__"
$env:TWINE_PASSWORD=(Read-Host "PyPI API token")
python -m twine upload dist/*
```

After a successful PyPI upload, do not reuse version `0.1.0`. Future package
changes must bump the version, for example to `0.1.1`.

## Feedback

Difend stores local feedback under `.difend/feedback/`. Exact false-positive matches can be suppressed only when the finding or manual-review fingerprint matches.

```bash
difend feedback --run-id <run-id> --finding-id <finding-id> --label false_positive --reason "explain why this is a false positive"
```

## Resources
- [**Resource 1:** AI-Generated Code Security Risks - Why Vulnerabilities Increase 2.74x and How to Prevent Them](https://www.softwareseni.com/ai-generated-code-security-risks-why-vulnerabilities-increase-2-74x-and-how-to-prevent-them/)
