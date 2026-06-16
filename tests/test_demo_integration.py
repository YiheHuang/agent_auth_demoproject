from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest

from agent_auth_registry.app import create_app as create_registry_app
from agent_auth_registry.storage import RegistryStore
from apps.agents.app import create_agent_app
from apps.console.app import create_console_app
from agent_auth_sdk.registry_security import hash_api_key
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
    required = {
        "DEMO_VAULT_ADDR": os.getenv("DEMO_VAULT_ADDR"),
        "DEMO_VAULT_TOKEN_FILE": os.getenv("DEMO_VAULT_TOKEN_FILE"),
        "DEMO_VAULT_TOKEN": os.getenv("DEMO_VAULT_TOKEN"),
        "DEMO_INTAKE_KMS_KEY_ID": os.getenv("DEMO_INTAKE_KMS_KEY_ID"),
        "DEMO_TRIAGE_KMS_KEY_ID": os.getenv("DEMO_TRIAGE_KMS_KEY_ID"),
        "DEMO_RESOLVER_KMS_KEY_ID": os.getenv("DEMO_RESOLVER_KMS_KEY_ID"),
        "DEMO_APPROVAL_KMS_KEY_ID": os.getenv("DEMO_APPROVAL_KMS_KEY_ID"),
    }
    missing = [name for name, value in required.items() if not value and name != "DEMO_VAULT_TOKEN"]
    if missing == ["DEMO_VAULT_TOKEN_FILE"] and os.getenv("DEMO_ALLOW_INSECURE_VAULT_TOKEN") == "1" and required["DEMO_VAULT_TOKEN"]:
        missing = []
    if missing:
        pytest.skip(f"Real Vault demo test requires: {', '.join(missing)}")
    base = get_demo_settings()
    return DemoSettings(
        root_dir=base.root_dir,
        runtime_dir=temp_runtime_dir,
        registry_path=temp_runtime_dir / "registry" / ".well-known" / "agent.json",
        database_path=temp_runtime_dir / "demo.sqlite3",
        metadata_cache_path=temp_runtime_dir / "metadata_cache.sqlite3",
        registry_base_url="http://registry.local/.well-known/agent.json",
        registry_publish_url="http://registry.local/registry/agents/publish",
        registry_client_id="developer-a",
        registry_api_key="secret-api-key",
        vault_addr=required["DEMO_VAULT_ADDR"],
        vault_token_file=required["DEMO_VAULT_TOKEN_FILE"],
        vault_token=required["DEMO_VAULT_TOKEN"],
        allow_insecure_vault_token=os.getenv("DEMO_ALLOW_INSECURE_VAULT_TOKEN", "0") == "1",
        vault_transit_mount=os.getenv("DEMO_VAULT_TRANSIT_MOUNT", "transit"),
        vault_namespace=os.getenv("DEMO_VAULT_NAMESPACE") or None,
        vault_ca_cert=os.getenv("DEMO_VAULT_CA_CERT") or None,
        vault_skip_verify=os.getenv("DEMO_VAULT_SKIP_VERIFY", "0") == "1",
        agent_kms_keys={
            "intake-agent": required["DEMO_INTAKE_KMS_KEY_ID"],
            "triage-agent": required["DEMO_TRIAGE_KMS_KEY_ID"],
            "resolver-agent": required["DEMO_RESOLVER_KMS_KEY_ID"],
            "approval-agent": required["DEMO_APPROVAL_KMS_KEY_ID"],
        },
        console_port=8010,
        host="127.0.0.1",
        organization=base.organization,
        agents=base.agents,
    )


@pytest.mark.anyio
async def test_normal_flow_and_attack_scenarios(temp_runtime_dir: Path) -> None:
    settings = build_settings(temp_runtime_dir)
    os.environ["AGENT_REGISTRY_PATH"] = str(settings.registry_path)
    os.environ["AGENT_REGISTRY_DB_PATH"] = str(temp_runtime_dir / "registry.sqlite3")
    store = RegistryStore(os.environ["AGENT_REGISTRY_DB_PATH"])
    store.create_developer(
        developer_id="dev-1",
        client_id="developer-a",
        api_key_hash=hash_api_key("secret-api-key"),
    )
    store.create_developer(
        developer_id="dev-2",
        client_id="rogue-client",
        api_key_hash=hash_api_key("rogue-api-key"),
    )
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

        stolen = await client.post("/api/scenarios/stolen-api-key")
        assert stolen.status_code == 200
        assert stolen.json()["status_code"] in {401, 409}

        owner_conflict = await client.post("/api/scenarios/owner-conflict")
        assert owner_conflict.status_code == 200
        assert owner_conflict.json()["status_code"] == 403

        detail_after_attacks = await client.get(f"/api/tickets/{ticket_id}?events_page=1&events_page_size=20")
        assert detail_after_attacks.status_code == 200
        attack_event_types = [event["event_type"] for event in detail_after_attacks.json()["events"]]
        assert "stolen_api_key_publish" in attack_event_types
        assert "owner_conflict_publish" in attack_event_types

        auth_events_after_attacks = await client.get("/api/auth-events?page=1&page_size=20")
        assert auth_events_after_attacks.status_code == 200
        registry_rejections = [
            event
            for event in auth_events_after_attacks.json()["items"]
            if event["target_agent"] == "registry" and event["result"] == "rejected"
        ]
        assert len(registry_rejections) >= 2
