from __future__ import annotations

import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SDK_REPO = ROOT.parent / "agent_auth_sdk"
for path in (ROOT, SDK_REPO):
    value = str(path)
    if value not in sys.path:
        sys.path.insert(0, value)


@pytest.fixture
def temp_runtime_dir(tmp_path: Path) -> Path:
    runtime = tmp_path / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    return runtime
