from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class Ticket(BaseModel):
    ticket_id: str
    title: str
    description: str
    category: str = "unknown"
    priority: str = "normal"
    status: str = "new"
    current_agent: str = "intake-agent"
    resolution: str | None = None
    created_at: datetime
    updated_at: datetime


class TicketEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    ticket_id: str
    event_type: str
    from_agent: str
    to_agent: str
    verification_result: str
    reason: str | None = None
    payload_summary: str
    created_at: datetime


class AuthEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    source_agent_id: str | None = None
    target_agent: str
    result: Literal["verified", "rejected"]
    error_code: str | None = None
    detail: str
    created_at: datetime


class CreateTicketRequest(BaseModel):
    title: str
    description: str


class IntakeRequest(BaseModel):
    ticket_id: str


class AgentTask(BaseModel):
    ticket_id: str
    action: str
    category: str | None = None
    priority: str | None = None
    risk_level: str | None = None
    context: str | None = None
    notes: list[str] = Field(default_factory=list)


class AgentTaskResult(BaseModel):
    ok: bool = True
    handled_by: str
    next_agent: str | None = None
    status: str | None = None
