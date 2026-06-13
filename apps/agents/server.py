from __future__ import annotations

import os
import sys

import uvicorn

from .app import create_agent_app
from shared.settings import get_demo_settings


def main() -> None:
    role = sys.argv[1] if len(sys.argv) > 1 else os.getenv("AGENT_ROLE")
    if not role:
        raise SystemExit("Usage: python -m apps.agents.server <agent-role>")
    settings = get_demo_settings()
    if role not in settings.agents:
        raise SystemExit(f"Unknown agent role: {role}")
    spec = settings.agents[role]
    uvicorn.run(create_agent_app(role, settings), host=settings.host, port=spec.port)


if __name__ == "__main__":
    main()
