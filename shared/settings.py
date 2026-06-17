from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_REMOTE_REGISTRY_URL = "http://192.144.228.237/.well-known/agent.json"
DEFAULT_REMOTE_REGISTRY_PUBLISH_URL = "http://192.144.228.237/registry/agents"
DEFAULT_REMOTE_REGISTRY_TOKEN = "123"


@dataclass(frozen=True, slots=True)
class LLMSettings:
    base_url: str = "https://yunwu.ai/v1"
    api_key: str = "sk-TP8v9yrsrv3WvhQldFsHShrWhNASAjF4ox1X8xMOguSzxZCN"
    model: str = "gpt-4o"
    temperature: float = 0.3
    max_tokens: int = 1024
    timeout: float = 30.0


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
    registry_client_id: str | None
    registry_api_key: str | None
    vault_addr: str | None
    vault_token_file: str | None
    vault_token: str | None
    allow_insecure_vault_token: bool
    vault_transit_mount: str
    vault_namespace: str | None
    vault_ca_cert: str | None
    vault_skip_verify: bool
    agent_kms_keys: dict[str, str | None]
    console_port: int
    host: str
    organization: str
    agents: dict[str, AgentSpec]
    llm: LLMSettings

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

    def agent_kms_key_id(self, role: str) -> str | None:
        return self.agent_kms_keys.get(role)

    def vault_verify(self) -> bool | str:
        if self.vault_skip_verify:
            return False
        return self.vault_ca_cert or True


def get_demo_settings() -> DemoSettings:
    root = Path(__file__).resolve().parents[1]
    runtime_dir = Path(os.getenv("DEMO_RUNTIME_DIR", root / "runtime"))
    host = os.getenv("DEMO_HOST", "127.0.0.1")
    registry_port = int(os.getenv("AGENT_REGISTRY_PORT", "8008"))
    registry_base_url = os.getenv("DEMO_REGISTRY_URL", "http://192.144.228.237/.well-known/agent.json")
    registry_publish_url = os.getenv("DEMO_REGISTRY_PUBLISH_URL", "http://192.144.228.237/registry/agents/publish")
    registry_path = Path(os.getenv("AGENT_REGISTRY_PATH", runtime_dir / "registry" / ".well-known" / "agent.json"))
    registry_token = os.getenv("DEMO_REGISTRY_TOKEN") or os.getenv("AGENT_REGISTRY_TOKEN")
    if registry_token is None and registry_publish_url == DEFAULT_REMOTE_REGISTRY_PUBLISH_URL:
        registry_token = DEFAULT_REMOTE_REGISTRY_TOKEN
    agents = {
        "coordinator-agent": AgentSpec("coordinator-agent", 8101, "Coordinator Agent"),
        "architecture-agent": AgentSpec("architecture-agent", 8102, "Architecture Agent"),
        "security-agent": AgentSpec("security-agent", 8103, "Security Agent"),
        "performance-agent": AgentSpec("performance-agent", 8104, "Performance Agent"),
        "compliance-agent": AgentSpec("compliance-agent", 8105, "Compliance Agent"),
    }
    return DemoSettings(
        root_dir=root,
        runtime_dir=runtime_dir,
        registry_path=registry_path,
        database_path=runtime_dir / "demo.sqlite3",
        metadata_cache_path=runtime_dir / "metadata_cache.sqlite3",
        registry_base_url=registry_base_url,
        registry_publish_url=registry_publish_url,
        registry_client_id=os.getenv("DEMO_REGISTRY_CLIENT_ID") or None,
        registry_api_key=os.getenv("DEMO_REGISTRY_API_KEY") or None,
        vault_addr=os.getenv("DEMO_VAULT_ADDR") or None,
        vault_token_file=os.getenv("DEMO_VAULT_TOKEN_FILE") or None,
        vault_token=os.getenv("DEMO_VAULT_TOKEN") or None,
        allow_insecure_vault_token=os.getenv("DEMO_ALLOW_INSECURE_VAULT_TOKEN", "0") == "1",
        vault_transit_mount=os.getenv("DEMO_VAULT_TRANSIT_MOUNT", "transit"),
        vault_namespace=os.getenv("DEMO_VAULT_NAMESPACE") or None,
        vault_ca_cert=os.getenv("DEMO_VAULT_CA_CERT") or None,
        vault_skip_verify=os.getenv("DEMO_VAULT_SKIP_VERIFY", "0") == "1",
        agent_kms_keys={
            "coordinator-agent": os.getenv("DEMO_COORDINATOR_KMS_KEY_ID"),
            "architecture-agent": os.getenv("DEMO_ARCHITECTURE_KMS_KEY_ID"),
            "security-agent": os.getenv("DEMO_SECURITY_KMS_KEY_ID"),
            "performance-agent": os.getenv("DEMO_PERFORMANCE_KMS_KEY_ID"),
            "compliance-agent": os.getenv("DEMO_COMPLIANCE_KMS_KEY_ID"),
        },
        console_port=8010,
        host=host,
        organization="Code Review & Security Audit Demo",
        agents=agents,
        llm=LLMSettings(
            base_url=os.getenv("LLM_BASE_URL", "https://yunwu.ai/v1"),
            api_key=os.getenv("LLM_API_KEY", "sk-TP8v9yrsrv3WvhQldFsHShrWhNASAjF4ox1X8xMOguSzxZCN"),
            model=os.getenv("LLM_MODEL", "gpt-4o"),
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.3")),
            max_tokens=int(os.getenv("LLM_MAX_TOKENS", "1024")),
            timeout=float(os.getenv("LLM_TIMEOUT", "30.0")),
        ),
    )
