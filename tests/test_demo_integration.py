"""Integration test: full code review flow + all 5 attack scenarios.

Requires a running Vault instance with Transit engine.  Set:
  DEMO_VAULT_ADDR, DEMO_VAULT_TOKEN (or DEMO_VAULT_TOKEN_FILE),
  DEMO_ALLOW_INSECURE_VAULT_TOKEN=1 (for dev),
  DEMO_COORDINATOR_KMS_KEY_ID, DEMO_ARCHITECTURE_KMS_KEY_ID,
  DEMO_SECURITY_KMS_KEY_ID, DEMO_PERFORMANCE_KMS_KEY_ID,
  DEMO_COMPLIANCE_KMS_KEY_ID, DEMO_LLM_API_KEY (optional)

Without these, the test is skipped.
"""

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
        "DEMO_COORDINATOR_KMS_KEY_ID": os.getenv("DEMO_COORDINATOR_KMS_KEY_ID"),
        "DEMO_ARCHITECTURE_KMS_KEY_ID": os.getenv("DEMO_ARCHITECTURE_KMS_KEY_ID"),
        "DEMO_SECURITY_KMS_KEY_ID": os.getenv("DEMO_SECURITY_KMS_KEY_ID"),
        "DEMO_PERFORMANCE_KMS_KEY_ID": os.getenv("DEMO_PERFORMANCE_KMS_KEY_ID"),
        "DEMO_COMPLIANCE_KMS_KEY_ID": os.getenv("DEMO_COMPLIANCE_KMS_KEY_ID"),
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
            "coordinator-agent": required["DEMO_COORDINATOR_KMS_KEY_ID"],
            "architecture-agent": required["DEMO_ARCHITECTURE_KMS_KEY_ID"],
            "security-agent": required["DEMO_SECURITY_KMS_KEY_ID"],
            "performance-agent": required["DEMO_PERFORMANCE_KMS_KEY_ID"],
            "compliance-agent": required["DEMO_COMPLIANCE_KMS_KEY_ID"],
        },
        console_port=8010,
        host="127.0.0.1",
        organization=base.organization,
        agents=base.agents,
        llm=base.llm,
    )


@pytest.mark.anyio
async def test_code_review_flow_and_attacks(temp_runtime_dir: Path) -> None:
    settings = build_settings(temp_runtime_dir)
    os.environ["AGENT_REGISTRY_PATH"] = str(settings.registry_path)
    os.environ["AGENT_REGISTRY_DB_PATH"] = str(temp_runtime_dir / "registry.sqlite3")
    store = RegistryStore(os.environ["AGENT_REGISTRY_DB_PATH"])
    store.create_developer(
        developer_id="dev-1", client_id="developer-a",
        api_key_hash=hash_api_key("secret-api-key"),
    )
    store.create_developer(
        developer_id="dev-2", client_id="rogue-client",
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
        # -- Submit code review -------------------------------------------------
        submit_response = await client.post(
            "/api/reviews",
            json={
                "title": "SQL Injection in login handler",
                "code": "def login(username, password):\n    query = 'SELECT * FROM users WHERE name = \\'' + username + '\\''\n    db.execute(query)\n    return True",
                "language_hint": "python",
            },
            timeout=300,
        )
        assert submit_response.status_code == 200
        data = submit_response.json()
        assert data.get("ok") is True
        review_id = data["review_id"]

        # -- Check review detail -------------------------------------------------
        detail = await client.get(f"/api/reviews/{review_id}")
        assert detail.status_code == 200
        payload = detail.json()
        assert payload["review"]["status"] == "completed"
        assert payload["review"]["overall_score"] is not None
        findings = payload["findings"]
        assert len(findings) >= 1  # SQL injection should be caught
        event_types = [e["event_type"] for e in payload["events"]]
        assert "review_completed" in event_types

        # -- List reviews --------------------------------------------------------
        reviews = await client.get("/api/reviews?page=1&page_size=5")
        assert reviews.status_code == 200
        assert reviews.json()["total"] >= 1

        # -- Auth events ---------------------------------------------------------
        auth = await client.get("/api/auth-events?page=1&page_size=10")
        assert auth.status_code == 200
        verified = [e for e in auth.json()["items"] if e["result"] == "verified"]
        assert len(verified) >= 4  # at least 4 specialist agents verified

        # -- Registry view -------------------------------------------------------
        registry = await client.get("/api/registry?page=1&page_size=10")
        assert registry.status_code == 200
        assert len(registry.json()["agents"]) == 5

        # -- Attack 1: Unregistered agent ----------------------------------------
        r = await client.post("/api/scenarios/unregistered")
        assert r.status_code == 200
        assert r.json()["status_code"] == 401

        # -- Attack 2: Tampered result -------------------------------------------
        r = await client.post("/api/scenarios/tampered")
        assert r.status_code == 200
        assert r.json()["status_code"] == 401

        # -- Attack 3: Nonce replay ----------------------------------------------
        r = await client.post("/api/scenarios/replay")
        assert r.status_code == 200
        assert r.json()["first"]["status_code"] == 200
        assert r.json()["second"]["status_code"] == 401

        # -- Attack 4: Stolen API Key --------------------------------------------
        r = await client.post("/api/scenarios/stolen-api-key")
        assert r.status_code == 200
        assert r.json()["status_code"] in {401, 403, 409}

        # -- Attack 5: Capability escalation -------------------------------------
        r = await client.post("/api/scenarios/capability-escalation")
        assert r.status_code == 200
        # Coordinator should reject because architecture agent lacks security capability
        assert r.json()["status_code"] in {401, 403}

        # -- Check attack auth events were recorded ------------------------------
        auth_after = await client.get("/api/auth-events?page=1&page_size=30")
        assert auth_after.status_code == 200
        attack_events = [
            e for e in auth_after.json()["items"]
            if e["target_agent"] == "attack-scenario"
        ]
        assert len(attack_events) >= 5
