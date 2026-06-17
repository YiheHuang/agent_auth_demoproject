"""Tests for LLM code review functions."""

from __future__ import annotations

import pytest

from shared.llm import (
    AnalysisResult,
    ReviewResult,
    SynthesisResult,
    analyze_code_submission,
    review_architecture,
    review_security,
    review_performance,
    review_compliance,
    synthesize_report,
)
from shared.prompts import (
    coordinator_analysis_prompt,
    architecture_review_prompt,
    security_review_prompt,
    performance_review_prompt,
    compliance_review_prompt,
    coordinator_synthesis_prompt,
)
from shared.settings import LLMSettings


@pytest.fixture
def llm_settings() -> LLMSettings:
    return LLMSettings(
        base_url="https://test.local/v1",
        api_key="test-key",
        model="gpt-4o",
        temperature=0.0,
        max_tokens=512,
        timeout=10.0,
    )


# -- Prompt tests ------------------------------------------------------------

def test_coordinator_analysis_prompt() -> None:
    system, user = coordinator_analysis_prompt("def foo(): pass", "python")
    assert "def foo(): pass" in user
    assert "language" in system
    assert "code_type" in system
    assert "complexity" in system


def test_architecture_review_prompt() -> None:
    system, user = architecture_review_prompt("code here", "python")
    assert "code here" in user
    assert "SOLID" in system
    assert "design_pattern" in system


def test_security_review_prompt() -> None:
    system, user = security_review_prompt("code", "javascript")
    assert "OWASP" in system
    assert "injection" in system
    assert "javascript" in user


def test_performance_review_prompt() -> None:
    system, user = performance_review_prompt("for loop code", "java")
    assert "algorithm_complexity" in system
    assert "n_plus_one_query" in system


def test_compliance_review_prompt() -> None:
    system, user = compliance_review_prompt("code", "python")
    assert "code_style" in system
    assert "documentation" in system


def test_synthesis_prompt() -> None:
    system, user = coordinator_synthesis_prompt(
        "code", "python", "analysis",
        {"score": 7, "summary": "ok", "findings": []},
        {"score": 5, "summary": "issues", "findings": [{"severity": "critical", "title": "SQLi"}]},
        {"score": 8, "summary": "fine", "findings": []},
        {"score": 6, "summary": "ok", "findings": []},
    )
    assert "risk_items" in system
    assert "overall_score" in system


# -- LLM Function tests (mocked) ---------------------------------------------

@pytest.mark.asyncio
async def test_analyze_code_submission(monkeypatch, llm_settings) -> None:
    async def mock_call(client, settings, system, user):
        return {"language": "python", "code_type": "module",
                "complexity": "medium", "review_focus": ["architecture", "security"],
                "summary": "A Python module with moderate complexity."}

    monkeypatch.setattr("shared.llm._call_llm", mock_call)
    result = await analyze_code_submission(llm_settings, "def foo(): pass")
    assert isinstance(result, AnalysisResult)
    assert result.language == "python"
    assert result.complexity == "medium"
    assert "architecture" in result.review_focus


@pytest.mark.asyncio
async def test_review_architecture(monkeypatch, llm_settings) -> None:
    async def mock_call(client, settings, system, user):
        return {"score": 6, "summary": "Architecture needs improvement.",
                "findings": [{"severity": "medium", "category": "solid_principle",
                              "title": "SRP Violation", "description": "Class has multiple responsibilities.",
                              "recommendation": "Split into smaller classes."}]}

    monkeypatch.setattr("shared.llm._call_llm", mock_call)
    result = await review_architecture(llm_settings, "code", "python")
    assert isinstance(result, ReviewResult)
    assert result.score == 6
    assert len(result.findings) == 1
    assert result.findings[0]["severity"] == "medium"


@pytest.mark.asyncio
async def test_review_security_finds_vulns(monkeypatch, llm_settings) -> None:
    async def mock_call(client, settings, system, user):
        return {"score": 3, "summary": "Multiple critical vulnerabilities found.",
                "findings": [
                    {"severity": "critical", "category": "injection",
                     "title": "SQL Injection", "description": "Unsanitized input in SQL query.",
                     "recommendation": "Use parameterized queries."},
                    {"severity": "high", "category": "sensitive_data",
                     "title": "Hardcoded API Key", "description": "API key exposed in source.",
                     "recommendation": "Move to environment variable."},
                ]}

    monkeypatch.setattr("shared.llm._call_llm", mock_call)
    result = await review_security(llm_settings, "code", "python")
    assert result.score == 3
    assert len(result.findings) == 2


@pytest.mark.asyncio
async def test_review_performance(monkeypatch, llm_settings) -> None:
    async def mock_call(client, settings, system, user):
        return {"score": 5, "summary": "Performance issues detected.",
                "findings": [{"severity": "high", "category": "n_plus_one_query",
                              "title": "N+1 Query", "description": "DB query inside loop.",
                              "recommendation": "Batch the queries."}]}

    monkeypatch.setattr("shared.llm._call_llm", mock_call)
    result = await review_performance(llm_settings, "code", "python")
    assert result.score == 5
    assert len(result.findings) == 1


@pytest.mark.asyncio
async def test_review_compliance(monkeypatch, llm_settings) -> None:
    async def mock_call(client, settings, system, user):
        return {"score": 4, "summary": "Multiple compliance issues.",
                "findings": [{"severity": "medium", "category": "documentation",
                              "title": "Missing Docstrings", "description": "None of the functions have docstrings.",
                              "recommendation": "Add docstrings to all public functions."}]}

    monkeypatch.setattr("shared.llm._call_llm", mock_call)
    result = await review_compliance(llm_settings, "code", "python")
    assert result.score == 4
    assert len(result.findings) == 1


@pytest.mark.asyncio
async def test_synthesize_report(monkeypatch, llm_settings) -> None:
    async def mock_call(client, settings, system, user):
        return {"overall_score": 5, "summary": "The code has security issues that must be fixed.",
                "architecture_score": 7, "security_score": 3,
                "performance_score": 6, "compliance_score": 5,
                "risk_items": [{"rank": 1, "severity": "critical", "category": "injection",
                                "title": "SQL Injection", "impact": "Data breach possible.",
                                "mitigation": "Use parameterized queries."}],
                "recommendations": ["Fix SQL injection immediately.", "Add input validation."]}

    monkeypatch.setattr("shared.llm._call_llm", mock_call)
    result = await synthesize_report(
        llm_settings, "code", "python", "analysis",
        {"score": 7, "summary": "", "findings": []},
        {"score": 3, "summary": "", "findings": []},
        {"score": 6, "summary": "", "findings": []},
        {"score": 5, "summary": "", "findings": []},
    )
    assert isinstance(result, SynthesisResult)
    assert result.overall_score == 5
    assert len(result.risk_items) == 1
    assert len(result.recommendations) == 2


@pytest.mark.asyncio
async def test_exception_propagates(monkeypatch, llm_settings) -> None:
    async def mock_call(client, settings, system, user):
        raise RuntimeError("API timeout")

    monkeypatch.setattr("shared.llm._call_llm", mock_call)
    with pytest.raises(RuntimeError, match="API timeout"):
        await analyze_code_submission(llm_settings, "code")
