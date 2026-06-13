from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import AuthEvent, Ticket, TicketEvent


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DemoStore:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS tickets (
                    ticket_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    category TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    status TEXT NOT NULL,
                    current_agent TEXT NOT NULL,
                    resolution TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ticket_events (
                    event_id TEXT PRIMARY KEY,
                    ticket_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    from_agent TEXT NOT NULL,
                    to_agent TEXT NOT NULL,
                    verification_result TEXT NOT NULL,
                    reason TEXT,
                    payload_summary TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS auth_events (
                    event_id TEXT PRIMARY KEY,
                    source_agent_id TEXT,
                    target_agent TEXT NOT NULL,
                    result TEXT NOT NULL,
                    error_code TEXT,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def create_ticket(self, title: str, description: str) -> Ticket:
        now = utc_now()
        ticket = Ticket(
            ticket_id=f"ticket-{int(now.timestamp() * 1000)}",
            title=title,
            description=description,
            created_at=now,
            updated_at=now,
        )
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tickets(ticket_id, title, description, category, priority, status, current_agent, resolution, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ticket.ticket_id,
                    ticket.title,
                    ticket.description,
                    ticket.category,
                    ticket.priority,
                    ticket.status,
                    ticket.current_agent,
                    ticket.resolution,
                    ticket.created_at.isoformat(),
                    ticket.updated_at.isoformat(),
                ),
            )
        return ticket

    def get_ticket(self, ticket_id: str) -> Ticket | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
        return Ticket.model_validate(dict(row)) if row else None

    def list_tickets(self) -> list[Ticket]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM tickets ORDER BY updated_at DESC").fetchall()
        return [Ticket.model_validate(dict(row)) for row in rows]

    def list_tickets_page(self, page: int = 1, page_size: int = 10) -> tuple[list[Ticket], int]:
        normalized_page, normalized_page_size = _normalize_page_args(page, page_size)
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM tickets").fetchone()[0]
            rows = conn.execute(
                "SELECT * FROM tickets ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (normalized_page_size, (normalized_page - 1) * normalized_page_size),
            ).fetchall()
        return [Ticket.model_validate(dict(row)) for row in rows], total

    def update_ticket(self, ticket_id: str, **fields: str | None) -> Ticket:
        fields["updated_at"] = utc_now().isoformat()
        assignments = ", ".join(f"{key} = ?" for key in fields)
        values = list(fields.values()) + [ticket_id]
        with self._connect() as conn:
            conn.execute(f"UPDATE tickets SET {assignments} WHERE ticket_id = ?", values)
        ticket = self.get_ticket(ticket_id)
        if ticket is None:
            raise KeyError(ticket_id)
        return ticket

    def add_ticket_event(self, event: TicketEvent) -> TicketEvent:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO ticket_events(event_id, ticket_id, event_type, from_agent, to_agent, verification_result, reason, payload_summary, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.ticket_id,
                    event.event_type,
                    event.from_agent,
                    event.to_agent,
                    event.verification_result,
                    event.reason,
                    event.payload_summary,
                    event.created_at.isoformat(),
                ),
            )
        return event

    def list_ticket_events(self, ticket_id: str) -> list[TicketEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM ticket_events WHERE ticket_id = ? ORDER BY created_at ASC",
                (ticket_id,),
            ).fetchall()
        return [TicketEvent.model_validate(dict(row)) for row in rows]

    def list_ticket_events_page(
        self,
        ticket_id: str,
        page: int = 1,
        page_size: int = 10,
    ) -> tuple[list[TicketEvent], int]:
        normalized_page, normalized_page_size = _normalize_page_args(page, page_size)
        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM ticket_events WHERE ticket_id = ?",
                (ticket_id,),
            ).fetchone()[0]
            rows = conn.execute(
                """
                SELECT * FROM ticket_events
                WHERE ticket_id = ?
                ORDER BY created_at ASC
                LIMIT ? OFFSET ?
                """,
                (ticket_id, normalized_page_size, (normalized_page - 1) * normalized_page_size),
            ).fetchall()
        return [TicketEvent.model_validate(dict(row)) for row in rows], total

    def add_auth_event(self, event: AuthEvent) -> AuthEvent:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO auth_events(event_id, source_agent_id, target_agent, result, error_code, detail, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.source_agent_id,
                    event.target_agent,
                    event.result,
                    event.error_code,
                    event.detail,
                    event.created_at.isoformat(),
                ),
            )
        return event

    def list_auth_events(self, limit: int = 200) -> list[AuthEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM auth_events ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [AuthEvent.model_validate(dict(row)) for row in rows]

    def list_auth_events_page(self, page: int = 1, page_size: int = 10) -> tuple[list[AuthEvent], int]:
        normalized_page, normalized_page_size = _normalize_page_args(page, page_size)
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM auth_events").fetchone()[0]
            rows = conn.execute(
                """
                SELECT * FROM auth_events
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (normalized_page_size, (normalized_page - 1) * normalized_page_size),
            ).fetchall()
        return [AuthEvent.model_validate(dict(row)) for row in rows], total


def _normalize_page_args(page: int, page_size: int) -> tuple[int, int]:
    return max(1, page), max(1, min(page_size, 50))
