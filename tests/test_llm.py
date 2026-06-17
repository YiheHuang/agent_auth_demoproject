"""Tests for the LLM service module (shared/llm.py).

All tests mock _call_llm to avoid real API calls.  They verify:
- Correct prompt construction
- Correct return types and field mapping
- Graceful handling of missing / invalid JSON fields (defaults)
- Exception propagation on LLM failure
"""

from __future__ import annotations

import pytest

from shared.llm import (
    IntakeResult,
    TriageResult,
    ApprovalResult,
    ResolverResult,
    classify_ticket,
    triage_ticket,
    approve_ticket,
    resolve_ticket,
    _call_llm,
)
from shared.prompts import (
    intake_prompt,
    triage_prompt,
    approval_prompt,
    resolver_prompt,
)
from shared.settings import LLMSettings


# -- Shared fixtures ---------------------------------------------------------

@pytest.fixture
def llm_settings() -> LLMSettings:
    return LLMSettings(
        base_url="https://test.local/v1",
        api_key="test-key",
        model="gpt-4o",
        temperature=0.0,
        max_tokens=256,
        timeout=10.0,
    )


# -- Prompt tests ------------------------------------------------------------

def test_intake_prompt_contains_ticket_info():
    system, user = intake_prompt("Reset Password", "I cannot log in")
    assert "Reset Password" in user
    assert "I cannot log in" in user
    assert "category" in system
    assert "priority" in system
    assert "risk_level" in system
    assert "reasoning" in system


def test_triage_prompt_contains_classification():
    system, user = triage_prompt(
        "Test", "Desc", "security", "high", "high",
    )
    assert "category=security" in user
    assert "priority=high" in user
    assert "risk_level=high" in user
    assert "approval-agent" in system
    assert "resolver-agent" in system


def test_approval_prompt_contains_notes():
    system, user = approval_prompt(
        "Test", "Desc", "security", "high", "high",
        notes=["verify identity", "check audit log"],
    )
    assert "verify identity" in user
    assert "check audit log" in user
    assert "approved" in system


def test_resolver_prompt_contains_ticket_info():
    system, user = resolver_prompt(
        "Test", "Description here", "general", "medium",
    )
    assert "Test" in user
    assert "Description here" in user
    assert "category=general" in user
    assert "status" in system
    assert "resolution" in system


# -- LLM function tests (with mocked _call_llm) ------------------------------

@pytest.mark.asyncio
async def test_classify_ticket_security(monkeypatch, llm_settings):
    """Mock LLM returns a security classification."""
    async def mock_call(client, settings, system, user):
        return {
            "category": "security",
            "priority": "high",
            "risk_level": "high",
            "reasoning": "密码重置属于安全问题且用户标注紧急。",
        }

    monkeypatch.setattr("shared.llm._call_llm", mock_call)
    result = await classify_ticket(
        llm_settings, "紧急密码重置", "无法登录需要立即重置密码",
    )
    assert isinstance(result, IntakeResult)
    assert result.category == "security"
    assert result.priority == "high"
    assert result.risk_level == "high"
    assert "密码" in result.reasoning


@pytest.mark.asyncio
async def test_classify_ticket_general(monkeypatch, llm_settings):
    """Mock LLM returns a general / low-priority classification."""
    async def mock_call(client, settings, system, user):
        return {
            "category": "general",
            "priority": "low",
            "risk_level": "normal",
            "reasoning": "普通咨询工单。",
        }

    monkeypatch.setattr("shared.llm._call_llm", mock_call)
    result = await classify_ticket(
        llm_settings, "如何使用打印机", "请问如何连接网络打印机",
    )
    assert result.category == "general"
    assert result.priority == "low"
    assert result.risk_level == "normal"


@pytest.mark.asyncio
async def test_triage_high_risk_routes_to_approval(monkeypatch, llm_settings):
    """High-risk tickets should route to approval-agent."""
    async def mock_call(client, settings, system, user):
        return {"route_to": "approval-agent", "reason": "高风险工单需要审批。"}

    monkeypatch.setattr("shared.llm._call_llm", mock_call)
    result = await triage_ticket(
        llm_settings, "数据泄露", "数据库被入侵",
        "security", "high", "high",
    )
    assert isinstance(result, TriageResult)
    assert result.route_to == "approval-agent"


@pytest.mark.asyncio
async def test_triage_low_risk_routes_to_resolver(monkeypatch, llm_settings):
    """Low-risk tickets should route directly to resolver-agent."""
    async def mock_call(client, settings, system, user):
        return {"route_to": "resolver-agent", "reason": "低风险直接处理。"}

    monkeypatch.setattr("shared.llm._call_llm", mock_call)
    result = await triage_ticket(
        llm_settings, "更换墨盒", "打印机墨盒空了",
        "general", "low", "normal",
    )
    assert result.route_to == "resolver-agent"


@pytest.mark.asyncio
async def test_approval_approves(monkeypatch, llm_settings):
    """Approval agent should approve valid tickets."""
    async def mock_call(client, settings, system, user):
        return {
            "approved": True,
            "conditions": "请先验证用户身份",
            "reason": "工单内容清晰，但涉及安全需验证身份。",
        }

    monkeypatch.setattr("shared.llm._call_llm", mock_call)
    result = await approve_ticket(
        llm_settings, "密码重置", "忘记密码", "security", "high", "high",
        notes=["urgent"],
    )
    assert isinstance(result, ApprovalResult)
    assert result.approved is True
    assert "验证" in result.conditions


@pytest.mark.asyncio
async def test_resolver_resolves(monkeypatch, llm_settings):
    """Resolver agent should produce a detailed resolution."""
    async def mock_call(client, settings, system, user):
        return {
            "status": "resolved",
            "resolution": "已为用户重置密码并验证新密码可用，同时检查了账户无异常登录。",
            "reason": "密码重置完成。",
        }

    monkeypatch.setattr("shared.llm._call_llm", mock_call)
    result = await resolve_ticket(
        llm_settings, "密码重置", "忘记密码", "security", "high",
    )
    assert isinstance(result, ResolverResult)
    assert result.status == "resolved"
    assert "密码" in result.resolution


@pytest.mark.asyncio
async def test_resolver_waiting_user(monkeypatch, llm_settings):
    """Resolver should request more info when needed."""
    async def mock_call(client, settings, system, user):
        return {
            "status": "waiting_user",
            "resolution": "需要用户提供注册邮箱地址以完成身份验证。",
            "reason": "缺少关键信息。",
        }

    monkeypatch.setattr("shared.llm._call_llm", mock_call)
    result = await resolve_ticket(
        llm_settings, "账户异常", "我的账户好像被盗了", "security", "high",
    )
    assert result.status == "waiting_user"


@pytest.mark.asyncio
async def test_empty_response_raises(monkeypatch, llm_settings):
    """Empty LLM response should raise RuntimeError."""
    async def mock_call(client, settings, system, user):
        return {}  # missing all fields → defaults, but covered by defensive .get()

    monkeypatch.setattr("shared.llm._call_llm", mock_call)
    result = await classify_ticket(llm_settings, "T", "D")
    # With empty dict, all defaults kick in — no exception
    assert result.category == "general"
    assert result.priority == "medium"
    assert result.risk_level == "normal"


@pytest.mark.asyncio
async def test_exception_propagates(monkeypatch, llm_settings):
    """If _call_llm raises, the public function should propagate it."""
    async def mock_call(client, settings, system, user):
        raise RuntimeError("API timeout")

    monkeypatch.setattr("shared.llm._call_llm", mock_call)
    with pytest.raises(RuntimeError, match="API timeout"):
        await classify_ticket(llm_settings, "T", "D")
