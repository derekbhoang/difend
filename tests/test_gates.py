from difend.agents.gates import find_gate_candidates, run_automated_gates
from difend.agents.schemas import LLMGateValidation, LLMGateValidationResult, Severity
from difend.agents.context import prepare_scan_context
from difend.diff import CodeDiff


class HallucinatingGateModel:
    model = "fake"

    def invoke_structured(self, system_prompt, payload, schema, node_name):
        return LLMGateValidationResult(
            validations=[
                LLMGateValidation(candidate_id="invented"),
            ]
        )


class EnrichingGateModel:
    model = "fake"

    def invoke_structured(self, system_prompt, payload, schema, node_name):
        return LLMGateValidationResult(
            validations=[
                LLMGateValidation(
                    candidate_id=payload["candidates"][0]["candidate_id"],
                    severity=Severity.CRITICAL,
                    confidence=0.99,
                    evidence="enriched evidence",
                    recommendation="enriched recommendation",
                )
            ]
        )


class EmptyGateModel:
    model = "fake"

    def invoke_structured(self, system_prompt, payload, schema, node_name):
        return LLMGateValidationResult(validations=[])


def _secret_diff():
    return CodeDiff(
        unstaged=(
            "diff --git a/config.py b/config.py\n"
            "--- a/config.py\n"
            "+++ b/config.py\n"
            "@@ -1,0 +1,1 @@\n"
            "+OPENAI_API_KEY = 'sk-this-is-a-secret'\n"
        ),
        staged="",
    )


def _context_from_added_lines(path: str, lines: list[str]):
    added = "\n".join(f"+{line}" for line in lines)
    return prepare_scan_context(
        CodeDiff(
            unstaged=(
                f"diff --git a/{path} b/{path}\n"
                f"--- a/{path}\n"
                f"+++ b/{path}\n"
                f"@@ -1,0 +1,{len(lines)} @@\n"
                f"{added}\n"
            ),
            staged="",
        )
    )


def test_gate_rules_create_candidates():
    context = prepare_scan_context(_secret_diff())

    candidates = find_gate_candidates(context)

    assert candidates
    assert candidates[0].vulnerability_type == "hardcoded_secret"


def test_gate_rules_detect_secret_keyword_inside_long_variable_name():
    context = prepare_scan_context(
        CodeDiff(
            unstaged=(
                "diff --git a/model.py b/model.py\n"
                "--- a/model.py\n"
                "+++ b/model.py\n"
                "@@ -1,0 +1,1 @@\n"
                "+OPENAI_API_KEY_ENV_VAR = 'placeholder-secret-value'\n"
            ),
            staged="",
        )
    )

    candidates = find_gate_candidates(context)

    assert candidates
    assert candidates[0].rule_id == "secret_scan"


def test_gate_rules_detect_openai_secret_like_value():
    context = prepare_scan_context(
        CodeDiff(
            unstaged=(
                "diff --git a/model.py b/model.py\n"
                "--- a/model.py\n"
                "+++ b/model.py\n"
                "@@ -1,0 +1,1 @@\n"
                "+CONFIG_VALUE = 'sk-proj-placeholderplaceholderplaceholder'\n"
            ),
            staged="",
        )
    )

    candidates = find_gate_candidates(context)

    assert candidates
    assert candidates[0].rule_id == "secret_value_scan"


def test_gate_llm_unknown_candidate_is_rejected():
    context = prepare_scan_context(_secret_diff())

    result, execution = run_automated_gates(context, HallucinatingGateModel())

    assert result.rejected_llm_outputs == ["invented"]
    assert result.findings
    assert execution.used_llm


def test_gate_llm_enriches_but_cannot_drop_candidates():
    context = prepare_scan_context(_secret_diff())

    empty_result, _ = run_automated_gates(context, EmptyGateModel())
    enriched_result, _ = run_automated_gates(context, EnrichingGateModel())

    assert len(empty_result.findings) == len(empty_result.candidates)
    assert empty_result.findings[0].gate_name == "secret_scan"
    assert enriched_result.findings[0].severity == Severity.CRITICAL
    assert enriched_result.findings[0].evidence == "enriched evidence"
    assert enriched_result.findings[0].gate_name == "secret_scan"


def test_marked_test_placeholder_secret_is_not_flagged():
    context = prepare_scan_context(
        CodeDiff(
            unstaged=(
                "diff --git a/tests/test_model.py b/tests/test_model.py\n"
                "--- a/tests/test_model.py\n"
                "+++ b/tests/test_model.py\n"
                "@@ -1,0 +1,1 @@\n"
                "+FAKE_OPENAI_API_KEY = 'sk-proj-placeholderplaceholderplaceholder'\n"
            ),
            staged="",
        )
    )

    candidates = find_gate_candidates(context)

    assert candidates == []


def test_real_secret_like_value_in_production_code_is_flagged():
    context = prepare_scan_context(
        CodeDiff(
            unstaged=(
                "diff --git a/src/config.py b/src/config.py\n"
                "--- a/src/config.py\n"
                "+++ b/src/config.py\n"
                "@@ -1,0 +1,1 @@\n"
                "+CONFIG_VALUE = 'sk-proj-livevaluewithmanycharacters'\n"
            ),
            staged="",
        )
    )

    candidates = find_gate_candidates(context)

    assert [candidate.rule_id for candidate in candidates] == ["secret_value_scan"]


def test_gate_rules_detect_aws_github_and_private_key_secret_values():
    context = prepare_scan_context(
        CodeDiff(
            unstaged=(
                "diff --git a/src/config.py b/src/config.py\n"
                "--- a/src/config.py\n"
                "+++ b/src/config.py\n"
                "@@ -1,0 +1,3 @@\n"
                "+AWS_KEY = 'AKIA1234567890ABCDEF'\n"
                "+GITHUB_TOKEN = 'github_pat_1234567890abcdefghijklmnopqrstuvwxyz'\n"
                "+KEY_HEADER = '-----BEGIN PRIVATE KEY-----'\n"
            ),
            staged="",
        )
    )

    candidates = find_gate_candidates(context)

    rule_ids = [candidate.rule_id for candidate in candidates]
    assert rule_ids.count("secret_value_scan") == 3
    assert "secret_scan" in rule_ids


def test_gate_rules_detect_expanded_shell_execution_patterns():
    context = prepare_scan_context(
        CodeDiff(
            unstaged=(
                "diff --git a/src/jobs.py b/src/jobs.py\n"
                "--- a/src/jobs.py\n"
                "+++ b/src/jobs.py\n"
                "@@ -1,0 +1,3 @@\n"
                "+subprocess.check_output(cmd, shell=True)\n"
                "+os.popen(user_input)\n"
                "+subprocess.run(command)\n"
            ),
            staged="",
        )
    )

    candidates = find_gate_candidates(context)

    assert [candidate.rule_id for candidate in candidates] == [
        "shell_execution",
        "shell_execution",
        "shell_execution",
    ]


def test_gate_rules_detect_disabled_tls_verification():
    context = prepare_scan_context(
        CodeDiff(
            unstaged=(
                "diff --git a/src/http.py b/src/http.py\n"
                "--- a/src/http.py\n"
                "+++ b/src/http.py\n"
                "@@ -1,0 +1,2 @@\n"
                "+requests.get(url, verify=False)\n"
                "+ssl._create_unverified_context()\n"
            ),
            staged="",
        )
    )

    candidates = find_gate_candidates(context)

    assert [candidate.rule_id for candidate in candidates] == [
        "weak_crypto",
        "weak_crypto",
    ]


def test_gate_rules_detect_risky_dependency_sources():
    context = prepare_scan_context(
        CodeDiff(
            unstaged=(
                "diff --git a/requirements.txt b/requirements.txt\n"
                "--- a/requirements.txt\n"
                "+++ b/requirements.txt\n"
                "@@ -1,0 +1,1 @@\n"
                "+package @ git+https://example.com/package.git\n"
            ),
            staged="",
        )
    )

    result, _ = run_automated_gates(context, None)

    assert [finding.gate_name for finding in result.findings] == [
        "dependency_direct_source",
    ]
    assert result.findings[0].severity == Severity.MEDIUM


def test_dependency_finding_includes_gate_name():
    context = prepare_scan_context(
        CodeDiff(
            unstaged=(
                "diff --git a/requirements.txt b/requirements.txt\n"
                "--- a/requirements.txt\n"
                "+++ b/requirements.txt\n"
                "@@ -1,0 +1,1 @@\n"
                "+requests==2.32.0\n"
            ),
            staged="",
        )
    )

    result, _ = run_automated_gates(context, None)

    assert result.findings
    assert result.findings[0].vulnerability_type == "dependency_risk"
    assert result.findings[0].gate_name == "dependency_change"


def test_scanner_regex_definitions_are_not_flagged_as_crypto_or_auth_bypass():
    context = prepare_scan_context(
        CodeDiff(
            unstaged=(
                "diff --git a/difend/agents/gates.py b/difend/agents/gates.py\n"
                "--- a/difend/agents/gates.py\n"
                "+++ b/difend/agents/gates.py\n"
                "@@ -1,0 +1,2 @@\n"
                "+WEAK_CRYPTO_RE = re.compile(r'(?i)\\\\b(md5|sha1|des|rc4)\\\\b')\n"
                "+DISABLED_AUTH_RE = re.compile(r'auth.*(false|skip|bypass)')\n"
            ),
            staged="",
        )
    )

    candidates = find_gate_candidates(context)

    assert candidates == []


def test_scanner_secret_regex_definitions_are_not_flagged():
    context = prepare_scan_context(
        CodeDiff(
            unstaged=(
                "diff --git a/difend/agents/gates.py b/difend/agents/gates.py\n"
                "--- a/difend/agents/gates.py\n"
                "+++ b/difend/agents/gates.py\n"
                "@@ -1,0 +1,2 @@\n"
                "+SECRET_VALUE_RE = re.compile(r'github_pat_[A-Za-z0-9_]{20,}')\n"
                "+SECRET_RE = re.compile(r'api_key\\\\s*=\\\\s*[\\\"\\\\'][^\\\"\\\\']{8,}')\n"
            ),
            staged="",
        )
    )

    candidates = find_gate_candidates(context)

    assert candidates == []


def test_gate_rules_detect_plaintext_password_handling_and_debug_mode():
    context = _context_from_added_lines(
        "test.py",
        [
            "password TEXT",
            'cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))',
            'cur.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))',
            "app.run(debug=True)",
        ],
    )

    candidates = find_gate_candidates(context)

    assert [candidate.vulnerability_type for candidate in candidates] == [
        "plaintext_password_storage",
        "plaintext_password_insert",
        "plaintext_password_comparison",
        "debug_mode_enabled",
    ]


def test_gate_rules_skip_safe_password_hashing_helpers():
    context = _context_from_added_lines(
        "auth.py",
        [
            "password_hash = generate_password_hash(password)",
            "is_valid = check_password_hash(user.password_hash, password)",
            "stored = bcrypt.hashpw(password.encode(), salt)",
            "hashlib.pbkdf2_hmac('sha256', password, salt, 100000)",
        ],
    )

    candidates = find_gate_candidates(context)

    assert [
        candidate.vulnerability_type
        for candidate in candidates
        if candidate.vulnerability_type.startswith("plaintext_password")
    ] == []


def test_gate_rules_detect_unsafe_deserialization_patterns():
    context = _context_from_added_lines(
        "views.py",
        [
            "obj = pickle.loads(request.data)",
            "config = yaml.load(request.data)",
            "value = marshal.loads(payload)",
        ],
    )

    candidates = find_gate_candidates(context)

    assert [candidate.vulnerability_type for candidate in candidates] == [
        "unsafe_deserialization",
        "unsafe_deserialization",
        "unsafe_deserialization",
    ]


def test_gate_rules_allow_safe_yaml_loader():
    context = _context_from_added_lines(
        "views.py",
        [
            "config = yaml.safe_load(request.data)",
            "config = yaml.load(request.data, Loader=yaml.SafeLoader)",
        ],
    )

    candidates = find_gate_candidates(context)

    assert [
        candidate
        for candidate in candidates
        if candidate.vulnerability_type == "unsafe_deserialization"
    ] == []


def test_gate_rules_detect_template_and_nosql_injection():
    context = _context_from_added_lines(
        "views.py",
        [
            "return render_template_string(request.args['template'])",
            'users.find({"$where": request.args["where"]})',
        ],
    )

    candidates = find_gate_candidates(context)

    assert [candidate.vulnerability_type for candidate in candidates] == [
        "template_injection",
        "nosql_injection",
    ]


def test_gate_rules_detect_open_redirect_and_path_traversal():
    context = _context_from_added_lines(
        "views.py",
        [
            'return redirect(request.args.get("next"))',
            'return send_file(request.args["path"])',
        ],
    )

    candidates = find_gate_candidates(context)

    assert [candidate.vulnerability_type for candidate in candidates] == [
        "open_redirect",
        "path_traversal",
    ]


def test_gate_rules_skip_path_traversal_when_line_has_validation():
    context = _context_from_added_lines(
        "views.py",
        [
            'return send_file(safe_join(base_dir, request.args["path"]))',
        ],
    )

    candidates = find_gate_candidates(context)

    assert [
        candidate
        for candidate in candidates
        if candidate.vulnerability_type == "path_traversal"
    ] == []


def test_gate_rules_detect_archive_cookie_cors_and_crypto_secret():
    context = _context_from_added_lines(
        "app.py",
        [
            "archive.extractall(upload_dir)",
            "response.set_cookie('session', token, secure=False)",
            'CORS(app, origins="*", supports_credentials=True)',
            "AES_KEY = 'hardcoded-encryption-key'",
        ],
    )

    candidates = find_gate_candidates(context)

    assert [candidate.vulnerability_type for candidate in candidates] == [
        "unsafe_archive_extraction",
        "insecure_cookie",
        "permissive_cors",
        "hardcoded_crypto_key",
    ]


def test_gate_rules_detect_risky_install_command():
    context = _context_from_added_lines(
        "Dockerfile",
        [
            "RUN pip install git+https://example.com/package.git",
        ],
    )

    candidates = find_gate_candidates(context)

    assert [candidate.rule_id for candidate in candidates] == [
        "dependency_install_command",
    ]
