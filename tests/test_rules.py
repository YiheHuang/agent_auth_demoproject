"""Tests for static fallback code review rules."""

from __future__ import annotations

from shared.rules import (
    analyze_code_submission,
    detect_language,
    review_architecture,
    review_compliance,
    review_performance,
    review_security,
    synthesize_report,
)


def test_detect_python() -> None:
    assert detect_language("import os\ndef foo():\n    pass") == "python"


def test_detect_javascript() -> None:
    assert detect_language("const x = 1;\nfunction foo() {\n  console.log(x);\n}") == "javascript"


def test_detect_unknown() -> None:
    assert detect_language("plain text with no code patterns") == "unknown"


def test_analyze_code_submission() -> None:
    result = analyze_code_submission("import os\nimport sys\n\ndef main():\n    print('hello')\n", "python")
    assert result.language == "python"
    assert result.complexity in ("low", "medium", "high")
    assert len(result.review_focus) >= 1


def test_review_security_finds_hardcoded_secret() -> None:
    code = 'password = "secret123"\napi_key = "sk-abc"\n'
    result = review_security(code, "python")
    assert len(result.findings) >= 1
    has_cred = any("硬编码" in f.get("title", "") for f in result.findings)
    assert has_cred


def test_review_security_finds_sql_injection() -> None:
    code = 'query = "SELECT * FROM users WHERE id = " + user_id'
    result = review_security(code, "python")
    has_injection = any("注入" in f.get("title", "") or "注入" in f.get("category", "")
                         for f in result.findings)
    assert has_injection


def test_review_architecture_finds_bare_except() -> None:
    code = "try:\n    risky()\nexcept:\n    pass"
    result = review_architecture(code, "python")
    assert len(result.findings) >= 1


def test_review_performance_finds_nested_loops() -> None:
    code = "for i in range(10):\n    for j in range(10):\n        process(i, j)"
    result = review_performance(code, "python")
    assert len(result.findings) >= 1


def test_review_compliance_finds_missing_docstring() -> None:
    code = "def add(a, b):\n    return a + b"
    result = review_compliance(code, "python")
    # pattern matches function without docstring
    assert result.score <= 7


def test_synthesize_report() -> None:
    findings = {
        "architecture": [],
        "security": [
            {"severity": "critical", "category": "injection",
             "title": "SQL Injection", "description": "found", "recommendation": "fix"},
        ],
        "performance": [],
        "compliance": [{"severity": "low", "category": "naming", "title": "Naming", "description": "d", "recommendation": "r"}],
    }
    result = synthesize_report("code", "python", "analysis", findings)
    assert 1 <= result.overall_score <= 10
    assert len(result.risk_items) >= 1
    assert result.risk_items[0]["severity"] == "critical"
