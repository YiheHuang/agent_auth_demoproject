from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_REMOTE_REGISTRY_URL = "http://192.144.228.237/.well-known/agent.json"
DEFAULT_REMOTE_REGISTRY_PUBLISH_URL = "http://192.144.228.237/registry/agents"
DEFAULT_REMOTE_REGISTRY_TOKEN = "123"


@dataclass(frozen=True, slots=True)
class AgentSpec:
    role: str
    port: int
    display_name: str

    @property
    def domain(self) -> str:
        return f"127.0.0.1:{self.port}"

    @property
    def base_url(self) -> str:
        return f"http://{self.domain}"

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}/tasks/handle"


@dataclass(frozen=True, slots=True)
class DemoSettings:
    root_dir: Path
    runtime_dir: Path
    registry_path: Path
    database_path: Path
    metadata_cache_path: Path
    registry_base_url: str
    registry_publish_url: str
    registry_token: str | None
    console_port: int
    host: str
    organization: str
    agents: dict[str, AgentSpec]

    def agent_dir(self, role: str) -> Path:
        return self.runtime_dir / "agents" / role

    def agent_keys_dir(self, role: str) -> Path:
        return self.agent_dir(role) / "keys"

    def agent_metadata_dir(self, role: str) -> Path:
        return self.agent_dir(role) / "metadata"

    def agent_url(self, role: str) -> str:
        return self.agents[role].base_url

    def console_url(self) -> str:
        return f"http://{self.host}:{self.console_port}"


def get_demo_settings() -> DemoSettings:
    root = Path(__file__).resolve().parents[1]
    runtime_dir = Path(os.getenv("DEMO_RUNTIME_DIR", root / "runtime"))
    host = os.getenv("DEMO_HOST", "127.0.0.1")
    registry_port = int(os.getenv("AGENT_REGISTRY_PORT", "8008"))
    registry_base_url = os.getenv("DEMO_REGISTRY_URL", DEFAULT_REMOTE_REGISTRY_URL)
    registry_publish_url = os.getenv("DEMO_REGISTRY_PUBLISH_URL", DEFAULT_REMOTE_REGISTRY_PUBLISH_URL)
    registry_path = Path(os.getenv("AGENT_REGISTRY_PATH", runtime_dir / "registry" / ".well-known" / "agent.json"))
    registry_token = os.getenv("DEMO_REGISTRY_TOKEN") or os.getenv("AGENT_REGISTRY_TOKEN")
    if registry_token is None and registry_publish_url == DEFAULT_REMOTE_REGISTRY_PUBLISH_URL:
        registry_token = DEFAULT_REMOTE_REGISTRY_TOKEN
    agents = {
        "intake-agent": AgentSpec("intake-agent", 8101, "Intake Agent"),
        "triage-agent": AgentSpec("triage-agent", 8102, "Triage Agent"),
        "resolver-agent": AgentSpec("resolver-agent", 8103, "Resolver Agent"),
        "approval-agent": AgentSpec("approval-agent", 8104, "Approval Agent"),
    }
    return DemoSettings(
        root_dir=root,
        runtime_dir=runtime_dir,
        registry_path=registry_path,
        database_path=runtime_dir / "demo.sqlite3",
        metadata_cache_path=runtime_dir / "metadata_cache.sqlite3",
        registry_base_url=registry_base_url,
        registry_publish_url=registry_publish_url,
        registry_token=registry_token,
        console_port=8010,
        host=host,
        organization="Agent Auth Demo",
        agents=agents,
    )
