from __future__ import annotations

import uvicorn

from .app import create_console_app
from shared.settings import get_demo_settings


def main() -> None:
    settings = get_demo_settings()
    uvicorn.run(create_console_app(settings), host=settings.host, port=settings.console_port)


if __name__ == "__main__":
    main()
