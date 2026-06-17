"""Data models for the Multi-Agent Code Review & Security Audit System.

Core entities:  CodeReview, ReviewFinding, ReviewReport, RiskItem, ReviewEvent
Inter-agent:   AgentTask, AgentTaskResult
Auth:          AuthEvent (unchanged from original)
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


# -- Core domain models ------------------------------------------------------

class CodeReview(BaseModel):
    review_id: str
    title: str
    code: str
    language: str = "unknown"
    status: str = "submitted"  # submitted | analyzing | in_review | synthesizing | completed | failed
    coordinator_analysis: str | None = None
    overall_score: int | None = None  # 1-10
    created_at: datetime
    updated_at: datetime


class ReviewFinding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    review_id: str
    agent_role: str        # architecture | security | performance | compliance
    category: str          # domain-specific (see categories in prompts)
    severity: str          # critical | high | medium | low | info
    title: str
    description: str
    recommendation: str
    code_snippet: str | None = None
    line_numbers: str | None = None  # e.g. "L42-L56"
    created_at: datetime


class RiskItem(BaseModel):
    rank: int              # 1 = highest risk
    severity: str
    category: str
    title: str
    impact: str
    mitigation: str


class ReviewReport(BaseModel):
    report_id: str = Field(default_factory=lambda: str(uuid4()))
    review_id: str
    overall_score: int     # 1-10
    summary: str           # executive summary
    architecture_score: int
    security_score: int
    performance_score: int
    compliance_score: int
    risk_items: list[RiskItem] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    created_at: datetime


class ReviewEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    review_id: str
    event_type: str        # user_submitted | coordinator_analyzed | agent_dispatched |
                           # agent_received | finding_returned | report_synthesized |
                           # review_completed | verification_failed
    from_agent: str
    to_agent: str
    verification_result: str  # verified | rejected | signed | n/a
    reason: str | None = None
    payload_summary: str
    created_at: datetime


# -- Inter-agent communication models ----------------------------------------

class AgentTask(BaseModel):
    review_id: str
    action: str            # review_architecture | review_security |
                           # review_performance | review_compliance
    code: str
    language: str
    context: str | None = None
    notes: list[str] = Field(default_factory=list)


class AgentTaskResult(BaseModel):
    ok: bool = True
    handled_by: str        # agent role
    review_id: str
    action: str
    score: int             # 1-10 domain score
    summary: str           # 2-3 sentence domain summary in Chinese
    findings: list[dict] = Field(default_factory=list)
    # Each dict: {severity, category, title, description, recommendation,
    #             code_snippet, line_numbers}


# -- Auth events (unchanged) -------------------------------------------------

class AuthEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    source_agent_id: str | None = None
    target_agent: str
    result: Literal["verified", "rejected"]
    error_code: str | None = None
    detail: str
    created_at: datetime


# -- Console request models --------------------------------------------------

class SubmitReviewRequest(BaseModel):
    title: str
    code: str
    language_hint: str | None = None
