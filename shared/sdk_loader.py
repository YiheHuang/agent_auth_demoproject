from __future__ import annotations

import sys
from pathlib import Path


def ensure_sdk_path() -> None:
    root = Path(__file__).resolve().parents[1]
    sdk_repo = root.parent / "agent_auth_sdk"
    for path in (root, sdk_repo):
        value = str(path)
        if value not in sys.path:
            sys.path.insert(0, value)
