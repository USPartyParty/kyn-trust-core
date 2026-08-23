"""KYN command-line entry points."""

import uvicorn

from kyn.config import get_settings


def api() -> None:
    settings = get_settings()
    uvicorn.run(
        "kyn.main:create_app",
        factory=True,
        host=settings.bind_host,
        port=settings.bind_port,
        proxy_headers=True,
        forwarded_allow_ips=settings.forwarded_allow_ips,
    )
