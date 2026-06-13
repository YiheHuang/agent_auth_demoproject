from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest

from agent_auth_registry.app import create_app as create_registry_app
from apps.agents.app import create_agent_app
from apps.console.app import create_console_app
from shared.models import AgentTask
from shared.settings import DemoSettings, get_demo_settings


class HostRouterTransport(httpx.AsyncBaseTransport):
    def __init__(self, mapping: dict[str, object]) -> None:
        self._mapping = mapping
        self._transports: dict[str, httpx.ASGITransport] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        key = request.url.host if request.url.port is None else f"{request.url.host}:{request.url.port}"
        if key not in self._mapping:
            raise RuntimeError(f"Unknown host: {key}")
        if key not in self._transports:
            self._transports[key] = httpx.ASGITransport(app=self._mapping[key])
        return await self._transports[key].handle_async_request(request)


def build_settings(temp_runtime_dir: Path) -> DemoSettings:
    base = get_demo_settings()
    return DemoSettings(
        root_dir=base.root_dir,
        runtime_dir=temp_runtime_dir,
        registry_path=temp_runtime_dir / "registry" / ".well-known" / "agent.json",
        database_path=temp_runtime_dir / "demo.sqlite3",
        metadata_cache_path=temp_runtime_dir / "metadata_cache.sqlite3",
        registry_base_url="http://registry.local/.well-known/agent.json",
        registry_publish_url="http://registry.local/registry/agents",
        registry_token=None,
        console_port=8010,
        host="127.0.0.1",
        organization=base.organization,
        agents=base.agents,
    )


@pytest.mark.anyio
async def test_normal_flow_and_attack_scenarios(temp_runtime_dir: Path) -> None:
    settings = build_settings(temp_runtime_dir)
    os.environ["AGENT_REGISTRY_PATH"] = str(settings.registry_path)
    registry_app = create_registry_app()
    apps: dict[str, object] = {"registry.local": registry_app}
    transport = HostRouterTransport(apps)

    def client_factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=transport)

    for role, spec in settings.agents.items():
        apps[spec.domain] = create_agent_app(role, settings, http_client_factory=client_factory)
    console_app = create_console_app(settings, http_client_factory=client_factory)
    apps["console.local"] = console_app

    async with httpx.AsyncClient(transport=transport, base_url="http://console.local") as client:
        create_response = await client.post(
            "/api/tickets",
            json={"title": "Urgent password reset", "description": "urgent password reset for executive login access"},
        )
        assert create_response.status_code == 200
        ticket_id = create_response.json()["ticket_id"]

        detail = await client.get(f"/api/tickets/{ticket_id}?events_page=1&events_page_size=20")
        assert detail.status_code == 200
        payload = detail.json()
        assert payload["ticket"]["status"] == "resolved"
        event_types = [event["event_type"] for event in payload["events"]]
        assert "approval_granted" in event_types
        assert "ticket_resolved" in event_types

        tickets = await client.get("/api/tickets?page=1&page_size=5")
        assert tickets.status_code == 200
        assert tickets.json()["total"] >= 1

        auth_events = await client.get("/api/auth-events?page=1&page_size=5")
        assert auth_events.status_code == 200

        registry = await client.get("/api/registry?page=1&page_size=10")
        assert registry.status_code == 200
        assert len(registry.json()["agents"]) == 4

        unregistered = await client.post("/api/scenarios/unregistered")
        assert unregistered.status_code == 200
        assert unregistered.json()["status_code"] == 401

        tampered = await client.post("/api/scenarios/tampered")
        assert tampered.status_code == 200
        assert tampered.json()["status_code"] == 401

        replay = await client.post("/api/scenarios/replay")
        assert replay.status_code == 200
        assert replay.json()["first"]["status_code"] == 200
        assert replay.json()["second"]["status_code"] == 401
