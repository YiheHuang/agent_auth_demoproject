"""Tests for DemoStore with the new code review schema."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from shared.models import (
    AuthEvent,
    ReviewEvent,
    ReviewFinding,
)
from shared.store import DemoStore, utc_now


@pytest.fixture
def store() -> DemoStore:
    tmp = tempfile.mkdtemp()
    db = Path(tmp) / "test.sqlite3"
    s = DemoStore(db)
    yield s
    # Force close all connections and clean up
    s._connect().close()
    try:
        os.unlink(str(db))
        os.rmdir(tmp)
    except OSError:
        pass


def test_create_and_get_review(store: DemoStore) -> None:
    review = store.create_review("Test review", "def foo(): pass")
    assert review.review_id.startswith("review-")
    assert review.status == "submitted"

    fetched = store.get_review(review.review_id)
    assert fetched is not None
    assert fetched.title == "Test review"


def test_update_review(store: DemoStore) -> None:
    review = store.create_review("Test", "code")
    updated = store.update_review(
        review.review_id, language="python", status="analyzing"
    )
    assert updated.language == "python"
    assert updated.status == "analyzing"


def test_list_reviews_pagination(store: DemoStore) -> None:
    for i in range(5):
        store.create_review(f"Review {i}", f"code {i}")
    reviews, total = store.list_reviews_page(page=1, page_size=3)
    assert len(reviews) == 3
    assert total == 5


def test_add_and_list_findings(store: DemoStore) -> None:
    review = store.create_review("Test", "code")
    f1 = ReviewFinding(
        review_id=review.review_id, agent_role="security",
        category="injection", severity="critical",
        title="SQL Injection", description="Found SQL injection",
        recommendation="Use parameterized queries",
        created_at=utc_now(),
    )
    f2 = ReviewFinding(
        review_id=review.review_id, agent_role="architecture",
        category="solid_principle", severity="medium",
        title="SRP violation", description="Class does too much",
        recommendation="Split into smaller classes",
        created_at=utc_now(),
    )
    store.add_finding(f1)
    store.add_finding(f2)
    findings = store.list_findings(review.review_id)
    assert len(findings) == 2
    assert findings[0].severity == "critical"  # critical sorted before medium


def test_review_events(store: DemoStore) -> None:
    review = store.create_review("Test", "code")
    event = ReviewEvent(
        review_id=review.review_id, event_type="user_submitted",
        from_agent="user", to_agent="coordinator-agent",
        verification_result="n/a",
        payload_summary="code submitted",
        created_at=utc_now(),
    )
    store.add_review_event(event)
    events, total = store.list_review_events_page(review.review_id)
    assert total == 1
    assert events[0].event_type == "user_submitted"


def test_auth_events(store: DemoStore) -> None:
    event = AuthEvent(
        source_agent_id="agent://127.0.0.1:8102/architecture-agent",
        target_agent="coordinator-agent", result="rejected",
        error_code="signature_mismatch",
        detail="signature verification failed",
        created_at=utc_now(),
    )
    store.add_auth_event(event)
    events, total = store.list_auth_events_page()
    assert total == 1
    assert events[0].result == "rejected"


def test_clear_all(store: DemoStore) -> None:
    review = store.create_review("Test", "code")
    store.add_finding(ReviewFinding(
        review_id=review.review_id, agent_role="security",
        category="test", severity="low", title="T", description="D",
        recommendation="R", created_at=utc_now(),
    ))
    store.add_auth_event(AuthEvent(
        target_agent="test", result="verified", detail="ok",
        created_at=utc_now(),
    ))
    counts = store.clear_all()
    assert counts["code_reviews"] == 1
    assert counts["review_findings"] == 1
    assert counts["auth_events"] == 1

    _, total_r = store.list_reviews_page()
    _, total_a = store.list_auth_events_page()
    assert total_r == 0
    assert total_a == 0
