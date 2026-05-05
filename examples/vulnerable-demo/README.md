# Difend Vulnerable Demo

This folder contains intentionally vulnerable code for testing `difend scan`.

Do not use this code in production. All secrets in this folder are fake demo
values made only to trigger scanner rules.

## What This Demo Contains

| File | Demo issue |
|------|------------|
| `config.py` | fake hardcoded API keys, tokens, password-like values |
| `fake_private_key.pem` | fake private key block |
| `app.py` | `eval`, `exec`, `shell=True`, unsafe file paths |
| `database.py` | SQL string interpolation and formatting |
| `auth.py` | suspicious auth, role, session, CSRF changes |
| `payments.py` | suspicious permission/business-logic changes |
| `upload.py` | unsafe upload paths and shell command execution |
| `crypto.py` | weak hashing and predictable token generation |
| `frontend.jsx` | unsafe HTML rendering example |
| `requirements.txt` | old dependency versions |
| `pyproject.toml` | old dependency versions |
| `package.json` | old JavaScript dependency versions |

## Test This Fixture

From the Difend repository:

```bash
export DIFEND_SRC="$(pwd)"
DEMO=$(mktemp -d /tmp/difend-vulnerable-demo.XXXXXX)

cd "$DEMO"
git init
printf '# vulnerable demo\n' > README.md
printf '.difend/\n' > .gitignore
git add README.md .gitignore
git -c user.name=Demo -c user.email=demo@example.com commit -m init

cp -R "$DIFEND_SRC/examples/vulnerable-demo/"* "$DEMO"/
PYTHONPATH="$DIFEND_SRC" python3 -m difend scan
```

Expected terminal output:

```text
Checking secrets... warning
Checking dependency changes... warning
Checking injection risks... warning
Checking auth and permission changes... manual review required
```

Inspect the output:

```bash
RUN=$(ls -td .difend/runs/* | head -1)
cat "$RUN/summary.md"
cat "$RUN/context-signals.md"
cat "$RUN/report.json"
```

Expected result:

- `summary.md` shows `Status: manual review required`
- `context-signals.md` contains many rule-based signals
- `report.json` contains structured `rule_signals`
- `findings.md` stays empty until `difend review` runs

## Optional Agent Review

If you have an OpenAI API key:

```bash
export OPENAI_API_KEY="sk-..."
PYTHONPATH="$DIFEND_SRC" python3 -m difend review "$RUN"
cat "$RUN/findings.md"
cat "$RUN/solution-proposals.md"
```

Do not commit a real API key.
