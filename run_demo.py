from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx


ROOT = Path(__file__).resolve().parent
SDK_REPO = ROOT.parent / "agent_auth_sdk"


def check_runtime_dependencies() -> None:
    try:
        import cryptography  # noqa: F401
        import agent_auth_sdk  # noqa: F401
        import agent_auth_registry  # noqa: F401
    except ModuleNotFoundError as exc:
        missing = exc.name or "unknown dependency"
        raise SystemExit(
            "Demo runtime dependency is missing: "
            f"{missing}\n"
            "Please run:\n"
            "  pip install -e .\n"
            "  pip install -e ..\\agent_auth_sdk\n"
        ) from exc


def build_env() -> dict[str, str]:
    env = os.environ.copy()
    pythonpath_parts = [str(ROOT), str(SDK_REPO)]
    if env.get("PYTHONPATH"):
        pythonpath_parts.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(pythonpath_parts)
    use_local_registry = env.get("DEMO_USE_LOCAL_REGISTRY", "0") == "1"
    env.setdefault("AGENT_REGISTRY_HOST", "127.0.0.1")
    env.setdefault("AGENT_REGISTRY_PORT", "8008")
    env.setdefault("AGENT_REGISTRY_PATH", str(ROOT / "runtime" / "registry" / ".well-known" / "agent.json"))
    env.setdefault("DEMO_HOST", "127.0.0.1")
    if use_local_registry:
        env.setdefault("DEMO_REGISTRY_URL", "http://127.0.0.1:8008/.well-known/agent.json")
        env.setdefault("DEMO_REGISTRY_PUBLISH_URL", "http://127.0.0.1:8008/registry/agents")
    else:
        env.setdefault("DEMO_REGISTRY_URL", "http://192.144.228.237/.well-known/agent.json")
        env.setdefault("DEMO_REGISTRY_PUBLISH_URL", "http://192.144.228.237/registry/agents")
    env.setdefault("DEMO_RUNTIME_DIR", str(ROOT / "runtime"))
    return env


def spawn_processes() -> list[subprocess.Popen[str]]:
    env = build_env()
    commands = []
    if env.get("DEMO_USE_LOCAL_REGISTRY", "0") == "1":
        commands.append([sys.executable, "-m", "agent_auth_registry.run"])
    commands.extend(
        [
            [sys.executable, "-m", "apps.agents.server", "intake-agent"],
        [sys.executable, "-m", "apps.agents.server", "triage-agent"],
        [sys.executable, "-m", "apps.agents.server", "resolver-agent"],
        [sys.executable, "-m", "apps.agents.server", "approval-agent"],
        [sys.executable, "-m", "apps.console.server"],
        ]
    )
    processes: list[subprocess.Popen[str]] = []
    for command in commands:
        processes.append(
            subprocess.Popen(
                command,
                cwd=ROOT,
                env=env,
                text=True,
            )
        )
    return processes


def wait_for_console(timeout_seconds: float = 30.0) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            response = httpx.get("http://127.0.0.1:8010/healthz", timeout=2.0)
            if response.status_code == 200:
                return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("Console did not become ready in time")


def terminate_processes(processes: list[subprocess.Popen[str]]) -> None:
    for process in processes:
        if process.poll() is None:
            process.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM)
    for process in processes:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


def main() -> None:
    check_runtime_dependencies()
    processes = spawn_processes()
    try:
        wait_for_console()
        print("Demo is ready.")
        print("Console:  http://127.0.0.1:8010")
        print(f"Registry: {build_env()['DEMO_REGISTRY_URL']}")
        if build_env().get("DEMO_USE_LOCAL_REGISTRY", "0") == "1":
            print("Registry mode: local")
        else:
            print("Registry mode: server")
        print("Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        terminate_processes(processes)


if __name__ == "__main__":
    main()
