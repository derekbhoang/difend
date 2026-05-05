# Difend

Difend scans the current Git diff, writes rule-based security context into a scan bundle, then can call a Codex agent review step to turn that context into confirmed findings.

## Test the Project

From the Difend repository:

```bash
python3 -m unittest discover
```

Expected result:

```text
Ran 11 tests
OK
```

## Demo: Scan a Risky Diff

For a larger ready-made demo, use `examples/vulnerable-demo/README.md`.

Use a clean temporary repository as the scan target:

```bash
cd /Users/user/Documents/Codex/2026-04-29/clone-code-nayf-v-https-github
export DIFEND_SRC="$(pwd)"

DEMO=$(mktemp -d /tmp/difend-demo.XXXXXX)
cd "$DEMO"
git init

printf '# Difend demo\n' > README.md
printf '.difend/\n' > .gitignore
printf 'def baseline():\n    return "safe"\n' > app.py

git add README.md .gitignore app.py
git -c user.name=Demo -c user.email=demo@example.com commit -m init
```

Add several risky changes:

```bash
cat > risky_injection.py <<'PY'
import subprocess


def run_user_code(user_input):
    return eval(user_input)


def run_shell(command):
    return subprocess.run(command, shell=True, check=False)


def find_user(cursor, username):
    return cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
PY

cat > settings.py <<'PY'
API_KEY = "abc123456789secret"
SESSION_TOKEN = "token_123456789abcdef"
PY

cat > pyproject.toml <<'PY'
[project]
name = "unsafe-demo"
dependencies = [
    "requests==2.19.0",
    "django==1.11",
]
PY

cat > auth.py <<'PY'
def can_login(user):
    return user.session is not None


def allow_admin_role(user):
    return user.role == "admin"


def skip_auth_for_debug(request):
    return request.headers.get("X-Debug-Bypass") == "1"
PY

cat > safe_code.py <<'PY'
def add(a, b):
    return a + b
PY
```

Run the rule-based scan:

```bash
PYTHONPATH="$DIFEND_SRC" python3 -m difend scan
```

Expected output includes:

```text
Checking secrets... warning
Checking dependency changes... warning
Checking injection risks... warning
Checking auth and permission changes... manual review required

Status: manual review required
```

Save the latest run folder:

```bash
RUN=$(ls -td .difend/runs/* | head -1)
echo "$RUN"
```

Inspect the scan bundle:

```bash
cat "$RUN/summary.md"
cat "$RUN/context-signals.md"
cat "$RUN/report.json"
cat "$RUN/findings.md"
```

Important files:

```text
summary.md            human-readable scan summary
context-signals.md    rule-based gate output
report.json           machine-readable context for Codex/agents
findings.md           agent-confirmed findings after difend review
solution-proposals.md agent-generated fix proposals after difend review
diff.patch            exact diff scanned
```

Before agent review, `findings.md` should say no agent-confirmed findings have been generated yet.

## Demo: Run Codex Agent Review

Create a new OpenAI API key and set it in your shell:

```bash
export OPENAI_API_KEY="sk-..."
```

Do not commit or paste API keys into files.

Run the review step:

```bash
PYTHONPATH="$DIFEND_SRC" python3 -m difend review "$RUN"
```

Expected output includes:

```text
Difend agent review started

Status: manual review required
Findings written to: ...
Solution proposals written to: ...
Report updated: ...
```

Inspect the agent output:

```bash
cat "$RUN/findings.md"
cat "$RUN/solution-proposals.md"
cat "$RUN/report.json"
```

After `difend review`, `report.json` should include:

```text
agent_review
findings
solution_proposals
```

## Demo: Fix and Scan Again

Replace the risky file with safer code:

```bash
cat > risky_injection.py <<'PY'
def run_user_code(user_input):
    return user_input


def run_shell(command):
    return ["disabled", command]


def find_user(cursor, username):
    return cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
PY

cat > settings.py <<'PY'
API_KEY = ""
SESSION_TOKEN = ""
PY

cat > auth.py <<'PY'
def can_login(user):
    return bool(user and user.session)
PY
```

Run Difend again:

```bash
PYTHONPATH="$DIFEND_SRC" python3 -m difend scan
```

If no rule-based signals remain, the status should be:

```text
Status: pass
```

## Clean Up

```bash
cd /tmp
rm -rf "$DEMO"
```
