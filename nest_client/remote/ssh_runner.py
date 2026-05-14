from __future__ import annotations

import logging
import subprocess
import time

from nest_client.remote.config import RemoteConfig

logger = logging.getLogger(__name__)

CONTAINER_PORT = 3000
# Remote host ports used for Docker port mapping (-p host_port:3000).
# Must not clash with any already-running containers on the host.
REMOTE_BASE_PORT = 4000


def _base_ssh_args(config: RemoteConfig) -> list[str]:
    return [
        "ssh",
        "-i", str(config.ssh_key),
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
    ]


def ssh_exec(config: RemoteConfig, command: str) -> str:
    """Run a shell command on the remote host and return stdout. Raises on non-zero exit."""
    args = _base_ssh_args(config) + [f"{config.user}@{config.host}", command]
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"SSH command failed (exit {result.returncode}): {command!r}\n"
            f"stderr: {result.stderr.strip()}"
        )
    return result.stdout


def _container_name(index: int) -> str:
    return f"nest-server-{index}"


def launch_server_instance(config: RemoteConfig, index: int) -> int:
    """
    Start a nest-server container on the remote host with a host-port mapping.
    Returns the remote host port that is mapped to the container's CONTAINER_PORT.

    The host port is ``REMOTE_BASE_PORT + index``.  Docker's port-mapping proxy
    takes care of bridging IPv4 host traffic into the container regardless of
    whether the server binds on IPv6 loopback (``::1``) inside the container.
    """
    name = _container_name(index)
    host_port = REMOTE_BASE_PORT + index
    cmd = (
        f"docker run -d --name {name}"
        f" --shm-size=2g"
        f" --privileged"
        f" --cap-add SYS_ADMIN --cap-add NET_ADMIN"
        f" --security-opt apparmor:unconfined"
        f" -v /tmp:/tmp -v /dev:/dev -v /sys/fs/cgroup:/sys/fs/cgroup:ro"
        f" -e RUST_LOG=nest_server=debug"
        f" -e NEST_SOCKET_ADDR=0.0.0.0:{CONTAINER_PORT}"
        f" -p {host_port}:{CONTAINER_PORT}"
        f" {config.image}"
    )
    logger.info(
        "Launching nest-server container %s on %s (host port %d -> container port %d)",
        name, config.host, host_port, CONTAINER_PORT,
    )
    ssh_exec(config, cmd)
    return host_port


def stop_server_instance(config: RemoteConfig, index: int) -> None:
    """Stop and remove the nest-server container for the given index."""
    name = _container_name(index)
    logger.info("Stopping nest-server container %s on %s", name, config.host)
    try:
        ssh_exec(config, f"docker stop {name} && docker rm {name}")
    except Exception as exc:
        logger.warning("Could not stop container %s: %s", name, exc)


def wait_for_websocket(host: str, port: int, timeout: int) -> bool:
    """
    Poll until a WebSocket connection to ws://host:port/ws succeeds,
    or timeout (seconds) elapses.

    Uses the same websockets library as the actual client so the probe
    is identical to a real connection attempt.
    """
    import asyncio

    async def _probe() -> bool:
        try:
            try:
                from websockets.asyncio.client import connect
            except ImportError:
                from websockets.client import connect  # type: ignore[no-redef]

            url = f"ws://{host}:{port}/ws"
            async with connect(url, open_timeout=3.0):
                return True
        except Exception:
            return False

    url = f"ws://{host}:{port}/ws"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ok = asyncio.run(_probe())
        if ok:
            return True
        logger.debug("WebSocket probe %s not ready yet, retrying…", url)
        time.sleep(1.0)
    return False


class SSHTunnel:
    """
    Local port-forward tunnel kept alive by a background ``ssh -L`` process.

    Forwards ``localhost:{local_port}`` → ``{remote_host}:{remote_port}``
    through the SSH connection defined by *config*.

    Typically ``remote_host`` is ``localhost`` (the remote machine itself) and
    ``remote_port`` is the host port Docker maps to the container, so traffic
    goes: local machine → SSH → remote host port → Docker proxy → container.
    """

    def __init__(
        self,
        config: RemoteConfig,
        local_port: int,
        remote_host: str,
        remote_port: int = CONTAINER_PORT,
    ):
        self._config = config
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self._proc: subprocess.Popen | None = None

    def start(self) -> None:
        args = _base_ssh_args(self._config) + [
            "-N",
            "-o", "ExitOnForwardFailure=yes",
            "-L", f"{self.local_port}:{self.remote_host}:{self.remote_port}",
            f"{self._config.user}@{self._config.host}",
        ]
        self._proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1.5)
        self._check_alive()
        logger.debug(
            "SSH tunnel open: localhost:%d -> %s:%d (via %s)",
            self.local_port, self.remote_host, self.remote_port, self._config.host,
        )

    def _check_alive(self) -> None:
        if self._proc is None or self._proc.poll() is None:
            return
        raise RuntimeError(
            f"SSH tunnel localhost:{self.local_port} -> "
            f"{self.remote_host}:{self.remote_port} "
            f"exited with code {self._proc.returncode}.\n"
            f"Hint: check that port {self.local_port} is not already in use "
            f"locally (lsof -i :{self.local_port})."
        )

    def stop(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        logger.debug("SSH tunnel closed: localhost:%d", self.local_port)

    def __enter__(self) -> SSHTunnel:
        self.start()
        return self

    def __exit__(self, *_) -> None:
        self.stop()
