"""SQLite storage layer for the Code Review & Security Audit system.

Tables: code_reviews, review_findings, review_events, auth_events
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import AuthEvent, CodeReview, ReviewEvent, ReviewFinding


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DemoStore:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self._db_path))
        connection.row_factory = sqlite3.Row
        return connection

    # -- schema ---------------------------------------------------------------

    def init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS code_reviews (
                    review_id     TEXT PRIMARY KEY,
                    title         TEXT NOT NULL,
                    code          TEXT NOT NULL,
                    language      TEXT NOT NULL DEFAULT 'unknown',
                    status        TEXT NOT NULL DEFAULT 'submitted',
                    coordinator_analysis TEXT,
                    overall_score INTEGER,
                    created_at    TEXT NOT NULL,
                    updated_at    TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS review_findings (
                    finding_id    TEXT PRIMARY KEY,
                    review_id     TEXT NOT NULL,
                    agent_role    TEXT NOT NULL,
                    category      TEXT NOT NULL,
                    severity      TEXT NOT NULL,
                    title         TEXT NOT NULL,
                    description   TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    code_snippet  TEXT,
                    line_numbers  TEXT,
                    created_at    TEXT NOT NULL,
                    FOREIGN KEY (review_id) REFERENCES code_reviews(review_id)
                );

                CREATE TABLE IF NOT EXISTS review_events (
                    event_id      TEXT PRIMARY KEY,
                    review_id     TEXT NOT NULL,
                    event_type    TEXT NOT NULL,
                    from_agent    TEXT NOT NULL,
                    to_agent      TEXT NOT NULL,
                    verification_result TEXT NOT NULL,
                    reason        TEXT,
                    payload_summary TEXT NOT NULL,
                    created_at    TEXT NOT NULL,
                    FOREIGN KEY (review_id) REFERENCES code_reviews(review_id)
                );

                CREATE TABLE IF NOT EXISTS auth_events (
                    event_id      TEXT PRIMARY KEY,
                    source_agent_id TEXT,
                    target_agent  TEXT NOT NULL,
                    result        TEXT NOT NULL,
                    error_code    TEXT,
                    detail        TEXT NOT NULL,
                    created_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_findings_review
                    ON review_findings(review_id);
                CREATE INDEX IF NOT EXISTS idx_events_review
                    ON review_events(review_id);
                CREATE INDEX IF NOT EXISTS idx_auth_created
                    ON auth_events(created_at);
                """
            )

    # -- code_reviews ---------------------------------------------------------

    def create_review(self, title: str, code: str) -> CodeReview:
        now = utc_now()
        review = CodeReview(
            review_id=f"review-{int(now.timestamp() * 1000)}",
            title=title,
            code=code[:65536],  # truncate for SQLite TEXT
            created_at=now,
            updated_at=now,
        )
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO code_reviews
                   (review_id, title, code, language, status,
                    coordinator_analysis, overall_score, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    review.review_id, review.title, review.code,
                    review.language, review.status,
                    review.coordinator_analysis, review.overall_score,
                    review.created_at.isoformat(), review.updated_at.isoformat(),
                ),
            )
        return review

    def get_review(self, review_id: str) -> CodeReview | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM code_reviews WHERE review_id = ?", (review_id,)
            ).fetchone()
        return CodeReview.model_validate(dict(row)) if row else None

    def list_reviews(self) -> list[CodeReview]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM code_reviews ORDER BY updated_at DESC"
            ).fetchall()
        return [CodeReview.model_validate(dict(row)) for row in rows]

    def list_reviews_page(
        self, page: int = 1, page_size: int = 10
    ) -> tuple[list[CodeReview], int]:
        npage, nsize = _normalize_page_args(page, page_size)
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM code_reviews").fetchone()[0]
            rows = conn.execute(
                "SELECT * FROM code_reviews ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (nsize, (npage - 1) * nsize),
            ).fetchall()
        return [CodeReview.model_validate(dict(row)) for row in rows], total

    def update_review(self, review_id: str, **fields: str | int | None) -> CodeReview:
        fields["updated_at"] = utc_now().isoformat()
        assignments = ", ".join(f"{key} = ?" for key in fields)
        values = list(fields.values()) + [review_id]
        with self._connect() as conn:
            conn.execute(
                f"UPDATE code_reviews SET {assignments} WHERE review_id = ?", values
            )
        review = self.get_review(review_id)
        if review is None:
            raise KeyError(review_id)
        return review

    # -- review_findings ------------------------------------------------------

    def add_finding(self, finding: ReviewFinding) -> ReviewFinding:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO review_findings
                   (finding_id, review_id, agent_role, category, severity,
                    title, description, recommendation, code_snippet,
                    line_numbers, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding.finding_id, finding.review_id, finding.agent_role,
                    finding.category, finding.severity, finding.title,
                    finding.description, finding.recommendation,
                    finding.code_snippet, finding.line_numbers,
                    finding.created_at.isoformat(),
                ),
            )
        return finding

    def list_findings(self, review_id: str) -> list[ReviewFinding]:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT * FROM review_findings
                   WHERE review_id = ? ORDER BY
                     CASE severity
                       WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                       WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
                     END, created_at ASC""",
                (review_id,),
            ).fetchall()
        return [ReviewFinding.model_validate(dict(row)) for row in rows]

    # -- review_events --------------------------------------------------------

    def add_review_event(self, event: ReviewEvent) -> ReviewEvent:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO review_events
                   (event_id, review_id, event_type, from_agent, to_agent,
                    verification_result, reason, payload_summary, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.event_id, event.review_id, event.event_type,
                    event.from_agent, event.to_agent,
                    event.verification_result, event.reason,
                    event.payload_summary, event.created_at.isoformat(),
                ),
            )
        return event

    def list_review_events_page(
        self, review_id: str, page: int = 1, page_size: int = 10
    ) -> tuple[list[ReviewEvent], int]:
        npage, nsize = _normalize_page_args(page, page_size)
        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM review_events WHERE review_id = ?",
                (review_id,),
            ).fetchone()[0]
            rows = conn.execute(
                """SELECT * FROM review_events
                   WHERE review_id = ? ORDER BY created_at ASC
                   LIMIT ? OFFSET ?""",
                (review_id, nsize, (npage - 1) * nsize),
            ).fetchall()
        return [ReviewEvent.model_validate(dict(row)) for row in rows], total

    # -- auth_events ----------------------------------------------------------

    def add_auth_event(self, event: AuthEvent) -> AuthEvent:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO auth_events
                   (event_id, source_agent_id, target_agent, result,
                    error_code, detail, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.event_id, event.source_agent_id, event.target_agent,
                    event.result, event.error_code, event.detail,
                    event.created_at.isoformat(),
                ),
            )
        return event

    def list_auth_events_page(
        self, page: int = 1, page_size: int = 10
    ) -> tuple[list[AuthEvent], int]:
        npage, nsize = _normalize_page_args(page, page_size)
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM auth_events").fetchone()[0]
            rows = conn.execute(
                "SELECT * FROM auth_events ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (nsize, (npage - 1) * nsize),
            ).fetchall()
        return [AuthEvent.model_validate(dict(row)) for row in rows], total

    # -- utility --------------------------------------------------------------

    def clear_all(self) -> dict[str, int]:
        with self._connect() as conn:
            reviews = conn.execute("SELECT COUNT(*) FROM code_reviews").fetchone()[0]
            findings = conn.execute("SELECT COUNT(*) FROM review_findings").fetchone()[0]
            rev_events = conn.execute("SELECT COUNT(*) FROM review_events").fetchone()[0]
            auth = conn.execute("SELECT COUNT(*) FROM auth_events").fetchone()[0]
            conn.execute("DELETE FROM review_findings")
            conn.execute("DELETE FROM review_events")
            conn.execute("DELETE FROM code_reviews")
            conn.execute("DELETE FROM auth_events")
        return {
            "code_reviews": reviews,
            "review_findings": findings,
            "review_events": rev_events,
            "auth_events": auth,
        }


def _normalize_page_args(page: int, page_size: int) -> tuple[int, int]:
    return max(1, page), max(1, min(page_size, 50))
