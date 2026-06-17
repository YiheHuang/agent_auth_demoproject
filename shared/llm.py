"""LLM service module — OpenAI SDK wrapper for code review decisions.

Provides typed async functions for each agent role:
  - analyze_code_submission      (Coordinator, step 1)
  - review_architecture          (Architecture Agent)
  - review_security              (Security Agent)
  - review_performance           (Performance Agent)
  - review_compliance            (Compliance Agent)
  - synthesize_report            (Coordinator, final step)

All functions share a common pattern: create AsyncOpenAI client, send
system + user prompts, parse JSON response into typed dataclasses.

On failure, every function raises an exception so callers can fall back
to shared/rules.py.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from openai import AsyncOpenAI

from . import prompts
from .settings import LLMSettings


# -- Typed result dataclasses ------------------------------------------------

@dataclass(slots=True)
class AnalysisResult:
    language: str
    code_type: str
    complexity: str
    review_focus: list[str] = field(default_factory=list)
    summary: str = ""


@dataclass(slots=True)
class ReviewResult:
    score: int
    summary: str
    findings: list[dict] = field(default_factory=list)


@dataclass(slots=True)
class SynthesisResult:
    overall_score: int
    summary: str
    architecture_score: int
    security_score: int
    performance_score: int
    compliance_score: int
    risk_items: list[dict] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


# -- Internal helpers --------------------------------------------------------

def _create_client(settings: LLMSettings) -> AsyncOpenAI:
    return AsyncOpenAI(
        base_url=settings.base_url,
        api_key=settings.api_key,
        timeout=settings.timeout,
    )


async def _call_llm(
    client: AsyncOpenAI,
    settings: LLMSettings,
    system: str,
    user: str,
) -> dict[str, Any]:
    response = await client.chat.completions.create(
        model=settings.model,
        temperature=settings.temperature,
        max_tokens=settings.max_tokens,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        response_format={"type": "json_object"},
    )
    content = response.choices[0].message.content
    if content is None:
        raise RuntimeError("LLM returned empty response")
    return json.loads(content)


# -- Public async functions --------------------------------------------------

async def analyze_code_submission(
    settings: LLMSettings,
    code: str,
    language_hint: str | None = None,
) -> AnalysisResult:
    client = _create_client(settings)
    system, user = prompts.coordinator_analysis_prompt(code, language_hint)
    data = await _call_llm(client, settings, system, user)
    return AnalysisResult(
        language=data.get("language", "unknown"),
        code_type=data.get("code_type", "unknown"),
        complexity=data.get("complexity", "medium"),
        review_focus=data.get("review_focus", ["architecture", "security", "performance", "compliance"]),
        summary=data.get("summary", ""),
    )


async def review_architecture(
    settings: LLMSettings,
    code: str,
    language: str,
    context: str | None = None,
) -> ReviewResult:
    client = _create_client(settings)
    system, user = prompts.architecture_review_prompt(code, language, context)
    data = await _call_llm(client, settings, system, user)
    return ReviewResult(
        score=data.get("score", 7),
        summary=data.get("summary", ""),
        findings=data.get("findings", []),
    )


async def review_security(
    settings: LLMSettings,
    code: str,
    language: str,
    context: str | None = None,
) -> ReviewResult:
    client = _create_client(settings)
    system, user = prompts.security_review_prompt(code, language, context)
    data = await _call_llm(client, settings, system, user)
    return ReviewResult(
        score=data.get("score", 7),
        summary=data.get("summary", ""),
        findings=data.get("findings", []),
    )


async def review_performance(
    settings: LLMSettings,
    code: str,
    language: str,
    context: str | None = None,
) -> ReviewResult:
    client = _create_client(settings)
    system, user = prompts.performance_review_prompt(code, language, context)
    data = await _call_llm(client, settings, system, user)
    return ReviewResult(
        score=data.get("score", 7),
        summary=data.get("summary", ""),
        findings=data.get("findings", []),
    )


async def review_compliance(
    settings: LLMSettings,
    code: str,
    language: str,
    context: str | None = None,
) -> ReviewResult:
    client = _create_client(settings)
    system, user = prompts.compliance_review_prompt(code, language, context)
    data = await _call_llm(client, settings, system, user)
    return ReviewResult(
        score=data.get("score", 7),
        summary=data.get("summary", ""),
        findings=data.get("findings", []),
    )


async def synthesize_report(
    settings: LLMSettings,
    code: str,
    language: str,
    coordinator_analysis: str,
    architecture_result: dict,
    security_result: dict,
    performance_result: dict,
    compliance_result: dict,
) -> SynthesisResult:
    client = _create_client(settings)
    system, user = prompts.coordinator_synthesis_prompt(
        code, language, coordinator_analysis,
        architecture_result, security_result,
        performance_result, compliance_result,
    )
    data = await _call_llm(client, settings, system, user)
    return SynthesisResult(
        overall_score=data.get("overall_score", 7),
        summary=data.get("summary", ""),
        architecture_score=data.get("architecture_score", 7),
        security_score=data.get("security_score", 7),
        performance_score=data.get("performance_score", 7),
        compliance_score=data.get("compliance_score", 7),
        risk_items=data.get("risk_items", []),
        recommendations=data.get("recommendations", []),
    )
