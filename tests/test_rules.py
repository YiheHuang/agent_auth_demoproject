from __future__ import annotations

from shared.models import Ticket
from shared.rules import classify_category, classify_priority, requires_approval, resolution_for
from shared.store import utc_now


def test_classify_security_and_high_priority() -> None:
    text = "Urgent password reset needed for login access"
    assert classify_category(text) == "security"
    assert classify_priority(text) == "high"


def test_high_risk_ticket_requires_approval() -> None:
    ticket = Ticket(
        ticket_id="t1",
        title="Critical login issue",
        description="urgent password reset required",
        category="security",
        priority="high",
        status="new",
        current_agent="triage-agent",
        created_at=utc_now(),
        updated_at=utc_now(),
    )
    assert requires_approval(ticket) is True


def test_resolution_waiting_user() -> None:
    ticket = Ticket(
        ticket_id="t2",
        title="General issue",
        description="Need info before continuing",
        category="general",
        priority="normal",
        status="new",
        current_agent="resolver-agent",
        created_at=utc_now(),
        updated_at=utc_now(),
    )
    status, _ = resolution_for(ticket)
    assert status == "waiting_user"
