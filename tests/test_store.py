from __future__ import annotations

from shared.models import AuthEvent, TicketEvent
from shared.store import DemoStore, utc_now


def test_store_writes_ticket_and_events(temp_runtime_dir) -> None:
    store = DemoStore(temp_runtime_dir / "demo.sqlite3")
    ticket = store.create_ticket("Test", "description")
    store.add_ticket_event(
        TicketEvent(
            ticket_id=ticket.ticket_id,
            event_type="created",
            from_agent="user",
            to_agent="intake-agent",
            verification_result="n/a",
            payload_summary="ticket created",
            created_at=utc_now(),
        )
    )
    store.add_auth_event(
        AuthEvent(
            source_agent_id="agent://demo/intake-agent",
            target_agent="triage-agent",
            result="verified",
            detail="ok",
            created_at=utc_now(),
        )
    )
    assert len(store.list_tickets()) == 1
    assert len(store.list_ticket_events(ticket.ticket_id)) == 1
    assert len(store.list_auth_events()) == 1
