from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


BASE_PORT = 3000


DEFAULT_IMAGE = "e2e-nest-server:latest"


@dataclass
class RemoteConfig:
    host: str
    user: str
    ssh_key: Path
    image: str = DEFAULT_IMAGE
    server_ready_timeout: int = 30


def parse_remote_config(raw: Any) -> RemoteConfig | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("descriptor.remote must be a mapping")

    host = raw.get("host")
    if not isinstance(host, str) or not host.strip():
        raise ValueError("descriptor.remote.host must be a non-empty string")

    user = raw.get("user")
    if not isinstance(user, str) or not user.strip():
        raise ValueError("descriptor.remote.user must be a non-empty string")

    ssh_key_str = raw.get("ssh_key")
    if not isinstance(ssh_key_str, str) or not ssh_key_str.strip():
        raise ValueError("descriptor.remote.ssh_key must be a non-empty string")
    ssh_key = Path(ssh_key_str).expanduser().resolve()
    if not ssh_key.exists():
        raise ValueError(f"descriptor.remote.ssh_key not found: {ssh_key}")

    image = str(raw.get("image", DEFAULT_IMAGE)).strip()
    if not image:
        raise ValueError("descriptor.remote.image must be a non-empty string")

    server_ready_timeout = raw.get("server_ready_timeout", 30)
    if not isinstance(server_ready_timeout, int) or server_ready_timeout < 1:
        raise ValueError("descriptor.remote.server_ready_timeout must be a positive integer")

    return RemoteConfig(
        host=host.strip(),
        user=user.strip(),
        ssh_key=ssh_key,
        image=image,
        server_ready_timeout=server_ready_timeout,
    )
