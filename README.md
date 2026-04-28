# Difend - Diff Defend

## Idea

### Pain Point

AI-assisted coding lets developers and Codex produce code changes quickly, but security review often becomes the bottleneck. A single diff can include hidden risks that are easy to miss during normal code review, especially when reviewers are also checking functionality, style, and correctness.

Automated security tools are useful for common issues like leaked secrets, vulnerable dependencies, injection patterns, and unsafe cryptography. However, they are weaker at detecting deeper security risks in authentication, authorisation, privilege boundaries, business logic, and sensitive data flows.

Teams need a lightweight workflow that checks only the code diff, catches common vulnerabilities automatically, and flags suspicious changes for human security review when deeper context is required.

## Workflow

Difend focuses only on the code diff. It does not try to review the whole repository unless the changed lines require related context.

### Execution Flow

1. Developer or Codex makes changes to the repository.
2. Developer runs:

```bash
difend diff_vul_check
```

3. The command triggers the `difend SDK`.
4. The `difend SDK` catches the current code diff.
5. The SDK sends the diff into two asynchronous security review directions:

- **Automated gates:** Detect common vulnerabilities in the diff, such as leaked secrets, vulnerable dependencies, injection risks, unsafe auth changes, weak cryptography, and sensitive data exposure. This should handle around 80% of routine security detection.
- **Security risks:** Look for suspicious code that may contain deeper flaws. The SDK starts from the diff, traces related files only when needed, and asks for manual review when the code may affect authentication, authorisation, privilege boundaries, secrets, personal data, database queries, file access, payments, cryptography, or session management. This should handle around 20% of cases where human verification is required.

6. Difend waits for both directions to finish.
7. Difend combines the results into one final security report.
8. The final status is one of:

- `pass`
- `fail`
- `manual review required`

### Final Output

The final report should include:

- Automated gate findings
- Security risks that require human verification
- Files and lines involved
- Recommended fixes
- Manual review checklist
- Final status: pass, fail, or manual review required

Core principle: review the diff first, trace context only when needed, and escalate uncertain security risks to a human.

## Roadmap

### 28/04/2026
- Agreement on final idea.
- Find resouces for implementation.

### 29/04/2026
- Implement the first version of the `difend diff_vul_check` command.
- Implement code diff capture from the current Git working tree.
- Define the core `difend SDK` interface:
  - input: repository path and diff
  - output: structured security report
- Build the automated gates runner.
- Add initial automated gates:
  - secrets scanning
  - dependency change detection
  - simple injection pattern checks
  - risky authentication or authorisation change detection
- Define a shared finding format with file, line, severity, evidence, gate name, and recommendation.
- Combine automated gate results into one partial report.
- Test the command against small sample diffs.

Goal for the day: `difend diff_vul_check` can capture a diff, run basic automated gates, and print a structured vulnerability report.

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
- Implement final statuses:
  - `pass`
  - `fail`
  - `manual review required`
- Polish CLI output for developer readability.
- Run end-to-end tests on sample vulnerable diffs.
- Document known limitations and next steps.

Goal for the day: Difend can run the full two-direction workflow and produce a final diff-only security review report.

## Resources
- [**Resource 1:** AI-Generated Code Security Risks - Why Vulnerabilities Increase 2.74x and How to Prevent Them](https://www.softwareseni.com/ai-generated-code-security-risks-why-vulnerabilities-increase-2-74x-and-how-to-prevent-them/)
