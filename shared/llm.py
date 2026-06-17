"""LLM service module -- OpenAI SDK wrapper for agent decision-making.

Provides typed async functions for each agent role's decision point.
All functions share a common pattern: create an AsyncOpenAI client,
send a system + user prompt, and parse the JSON response into a
typed dataclass.

On any failure (network, parse error, empty response), an exception is
raised so callers can fall back to static rules.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from openai import AsyncOpenAI

from .prompts import (
    approval_prompt,
    intake_prompt,
    resolver_prompt,
    triage_prompt,
)
from .settings import LLMSettings


# -- Typed result dataclasses ------------------------------------------------

@dataclass(slots=True)
class IntakeResult:
    category: str       # "security" | "finance" | "general"
    priority: str       # "high" | "medium" | "low"
    risk_level: str     # "high" | "normal"
    reasoning: str      # 1-2 sentence explanation in Chinese


@dataclass(slots=True)
class TriageResult:
    route_to: str       # "approval-agent" | "resolver-agent"
    reason: str         # 1-2 sentence explanation in Chinese


@dataclass(slots=True)
class ApprovalResult:
    approved: bool
    conditions: str     # extra notes for the resolver (or "")
    reason: str         # 1-2 sentence explanation in Chinese


@dataclass(slots=True)
class ResolverResult:
    status: str         # "resolved" | "waiting_user"
    resolution: str     # detailed resolution text in Chinese
    reason: str         # 1 sentence explanation in Chinese


# -- Internal helpers --------------------------------------------------------

def _create_client(settings: LLMSettings) -> AsyncOpenAI:
    """Create an AsyncOpenAI client configured from LLMSettings."""
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
    """Send a system + user prompt and return the parsed JSON response.

    Raises RuntimeError if the LLM returns empty content or the JSON is
    unparseable.
    """
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


# -- Public async decision functions -----------------------------------------

async def classify_ticket(
    settings: LLMSettings,
    title: str,
    description: str,
) -> IntakeResult:
    """Classify a new ticket: category, priority, risk_level."""
    client = _create_client(settings)
    system, user = intake_prompt(title, description)
    data = await _call_llm(client, settings, system, user)
    return IntakeResult(
        category=data.get("category", "general"),
        priority=data.get("priority", "medium"),
        risk_level=data.get("risk_level", "normal"),
        reasoning=data.get("reasoning", ""),
    )


async def triage_ticket(
    settings: LLMSettings,
    title: str,
    description: str,
    category: str,
    priority: str,
    risk_level: str,
) -> TriageResult:
    """Decide where to route a classified ticket."""
    client = _create_client(settings)
    system, user = triage_prompt(title, description, category, priority, risk_level)
    data = await _call_llm(client, settings, system, user)
    return TriageResult(
        route_to=data.get("route_to", "resolver-agent"),
        reason=data.get("reason", ""),
    )


async def approve_ticket(
    settings: LLMSettings,
    title: str,
    description: str,
    category: str,
    priority: str,
    risk_level: str,
    notes: list[str] | None = None,
) -> ApprovalResult:
    """Approve or reject a high-risk ticket before resolution."""
    client = _create_client(settings)
    system, user = approval_prompt(
        title, description, category, priority, risk_level, notes
    )
    data = await _call_llm(client, settings, system, user)
    return ApprovalResult(
        approved=data.get("approved", True),
        conditions=data.get("conditions", ""),
        reason=data.get("reason", ""),
    )


async def resolve_ticket(
    settings: LLMSettings,
    title: str,
    description: str,
    category: str,
    priority: str,
    notes: list[str] | None = None,
) -> ResolverResult:
    """Generate a resolution for a ticket."""
    client = _create_client(settings)
    system, user = resolver_prompt(title, description, category, priority, notes)
    data = await _call_llm(client, settings, system, user)
    return ResolverResult(
        status=data.get("status", "resolved"),
        resolution=data.get("resolution", ""),
        reason=data.get("reason", ""),
    )
