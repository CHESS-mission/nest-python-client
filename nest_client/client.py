"""
nest_client.client

Python client library for the CHESS NEST simulator.

Implements:
- AsyncNestClient: fully asynchronous WebSocket client matching NEST's JSON API
- NestClient: synchronous wrapper for simple scripting (blocking API)

Protocol reference (from NEST Rust backend):

Client → Server (JSON messages):
    {"action": "start"}
    {"action": "stop"}
    {"action": "upload_topology", "topology_yaml": "<YAML string>"}
    {"action": "command", "component": "Computer A", "command": "pause", "arguments": {...}}
    {"action": "set_env", "variable": "temp", "value": 23.2}

Server → Client (JSON messages):
    {"type": "status", "state": "running", "topology": {...}, "started_at": "2025-09-22T12:34:56Z"}
    {"type": "event", "component": "...", "event": "...", "data": {...}}
    {"type": "log", "timestamp": "...", "level": "...", "component": "...", "message": "..."}
    {"type": "error", "message": "..."}

References:
- src/api/lib.rs for serialization rules (serde(tag="action"/"type"))
- src/server/server.rs for WebSocket message dispatch
- src/server/simulator.rs for state transitions (Idle → Ready → Running)
"""

import asyncio
import json
import logging
import threading
import time
from typing import Any, Dict, Optional, Union

from .config import DEFAULT_URL, DEFAULT_TIMEOUT

#  WebSockets import (compatible with v13+)
try:
    from websockets.asyncio.client import connect, ClientConnection  # type: ignore[attr-defined]
except ImportError:
    try:
        from websockets.client import connect, ClientConnection       # type: ignore[attr-defined]
    except ImportError:
        from websockets.legacy.client import connect, WebSocketClientProtocol as ClientConnection  # type: ignore[attr-defined]

WebSocketClientProtocol = ClientConnection  # type: ignore[attr-defined]



logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s", "%H:%M:%S")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# ----------------------------------------------------------------------
# Exceptions
# ----------------------------------------------------------------------

from .exceptions import NestError, NestTimeoutError

# ----------------------------------------------------------------------
# Asynchronous client (core implementation)
# ----------------------------------------------------------------------

class AsyncNestClient:
    """Asynchronous WebSocket client for the CHESS NEST simulator."""

    def __init__(self, url: str = DEFAULT_URL, default_timeout: float = DEFAULT_TIMEOUT):
        self.url = url
        self.ws: Optional[WebSocketClientProtocol] = None
        self._recv_task: Optional[asyncio.Task] = None
        self._default_timeout = default_timeout
        self._send_lock = asyncio.Lock()

        self._msg_queue: asyncio.Queue = asyncio.Queue()
        self._connected = asyncio.Event()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------
    async def connect(self) -> None:
        """Connect to the NEST WebSocket server."""
        logger.info("Connecting to NEST at %s", self.url)
        try:
            self.ws = await connect(self.url)  # type: ignore[attr-defined]
            self._connected.set()
            self._recv_task = asyncio.create_task(self._recv_loop(), name="nest_recv")
            logger.info("Connected.")
        except Exception as e:
            raise NestError(f"Failed to connect: {e}") from e


    async def disconnect(self) -> None:
        """Disconnect cleanly from the server."""
        if not self.ws:
            return
        logger.info("Disconnecting from NEST.")
        if self._recv_task:
            self._recv_task.cancel()
            try:
                await self._recv_task
            except asyncio.CancelledError:
                pass
        try:
            await self.ws.close()  # type: ignore[attr-defined]
        finally:
            self.ws = None
            self._connected.clear()
        logger.info("Disconnected.")

    # ------------------------------------------------------------------
    # Sending actions (client → server)
    # ------------------------------------------------------------------
    async def _send(self, payload: Dict[str, Any]) -> None:
        """Safely send a JSON payload over the WebSocket connection."""
        if not self.ws:
            raise NestError("WebSocket is not connected.")

        # Handle modern websockets API (v12+)
        try:
            if getattr(self.ws, "closed", False):
                raise NestError("WebSocket connection already closed.")
        except Exception:
            pass  # `.closed` may not exist or be awaitable, so we ignore

        msg = json.dumps(payload)
        async with self._send_lock:
            try:
                await self.ws.send(msg)  # type: ignore[attr-defined]
                logger.debug("Sent: %s", msg)
            except Exception as e:
                raise NestError(f"Failed to send message: {e}") from e


    async def start(self) -> None:
        await self._send({"action": "start"})

    async def stop(self) -> None:
        await self._send({"action": "stop"})

    async def upload_topology(self, topology_yaml: str) -> None:
        await self._send({"action": "upload_topology", "topology_yaml": topology_yaml})

    async def set_env(self, variable: str, value: Any) -> None:
        await self._send({"action": "set_env", "variable": variable, "value": value})

    async def send_command(
        self, component: str, command: str, arguments: Optional[Dict[str, Any]] = None
    ) -> None:
        args = arguments if arguments is not None else {}
        await self._send(
            {"action": "command", "component": component, "command": command, "arguments": args}
        )

    # ------------------------------------------------------------------
    # Receiving (server → client)
    # ------------------------------------------------------------------
    async def _recv_loop(self) -> None:
        """Background loop: receives and enqueues messages."""
        assert self.ws is not None, "WebSocket not connected"
        try:
            async for raw in self.ws:  # type: ignore[attr-defined]
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    logger.warning("Non-JSON message: %s", raw)
                    continue
                await self._msg_queue.put(msg)
                logger.debug("Received: %s", msg)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.exception("Receive loop error: %s", e)

    async def next_message(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        """Return the next message from the server, or raise on timeout."""
        timeout = timeout or self._default_timeout
        try:
            msg = await asyncio.wait_for(self._msg_queue.get(), timeout)
            return msg
        except asyncio.TimeoutError:
            raise NestTimeoutError("Timed out waiting for message")

    async def wait_for_type(
        self,
        type_: str,
        key: Optional[str] = None,
        value: Optional[Any] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Wait until a message of a given type (and optionally matching key/value) arrives."""
        end = time.time() + (timeout or self._default_timeout)
        while True:
            remaining = end - time.time()
            if remaining <= 0:
                raise NestTimeoutError(f"Timeout waiting for type={type_}")
            msg = await self.next_message(timeout=remaining)
            if msg.get("type") == type_:
                if key is None or msg.get(key) == value:
                    return msg

    # Convenience wrappers
    async def wait_for_status(self, state: str, timeout: Optional[float] = None) -> Dict[str, Any]:
        return await self.wait_for_type("status", "state", state, timeout)

    async def wait_for_log(
        self, level: Optional[str] = None, timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        """Wait for next log message, optionally filtering by level."""
        end = time.time() + (timeout or self._default_timeout)
        while True:
            remaining = end - time.time()
            if remaining <= 0:
                raise NestTimeoutError("Timeout waiting for log")
            msg = await self.next_message(timeout=remaining)
            if msg.get("type") == "log" and (level is None or msg.get("level") == level):
                return msg

    async def wait_for_event(
        self,
        component: Optional[str] = None,
        event: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Wait for an event message matching the given component/event."""
        end = time.time() + (timeout or self._default_timeout)
        while True:
            remaining = end - time.time()
            if remaining <= 0:
                raise NestTimeoutError("Timeout waiting for event")
            msg = await self.next_message(timeout=remaining)
            if msg.get("type") == "event":
                if (component is None or msg.get("component") == component) and (
                    event is None or msg.get("event") == event
                ):
                    return msg


# ----------------------------------------------------------------------
# Synchronous wrapper
# ----------------------------------------------------------------------

class NestClient:
    """
    Synchronous (blocking) wrapper for AsyncNestClient.

    Example:
        from nest_client.client import NestClient

        client = NestClient("ws://localhost:8080/ws")
        client.connect()
        client.upload_topology(open("topology.yaml").read())
        client.start()
        log = client.wait_for_log(timeout=5)
        client.stop()
        client.disconnect()
    """
    def __init__(self, url: str = DEFAULT_URL, default_timeout: float = DEFAULT_TIMEOUT):
        self._url = url
        self._default_timeout = default_timeout
        self._loop = asyncio.new_event_loop()
        self._thread: Optional[threading.Thread] = None
        self._async_client: Optional[AsyncNestClient] = None
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _run_loop(self):
        """Run asyncio event loop in a background thread."""
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_forever()
        finally:
            self._loop.close()

    def _run(self, coro):
        """Submit a coroutine to the running loop and return its result."""
        if not asyncio.iscoroutine(coro):
            raise TypeError(f"Expected coroutine, got {type(coro)}")
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def connect(self) -> None:
        """Start background event loop and connect to the NEST server."""
        if self._thread and self._thread.is_alive():
            raise NestError("Already connected.")
        self._async_client = AsyncNestClient(self._url, self._default_timeout)
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        # Corrected: call coroutine, not pass function
        self._run(self._async_client.connect())

    def disconnect(self) -> None:
        """Disconnect and stop the background loop."""
        if not self._async_client:
            return
        # Corrected: call coroutine
        self._run(self._async_client.disconnect())
        # Gracefully stop event loop
        self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=1)
        self._thread = None
        self._async_client = None

    # ------------------------------------------------------------------
    # Client actions
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Send 'start' command to the simulator."""
        assert self._async_client is not None, "Client is not connected"
        self._run(self._async_client.start())

    def stop(self) -> None:
        """Send 'stop' command to the simulator."""
        assert self._async_client is not None, "Client is not connected"
        self._run(self._async_client.stop())

    def upload_topology(self, yaml: str | bytes) -> None:
        """Upload topology YAML string to the simulator."""
        if isinstance(yaml, bytes):
            yaml = yaml.decode("utf-8")
        assert isinstance(yaml, str)    
        assert self._async_client is not None, "Client is not connected"
        self._run(self._async_client.upload_topology(yaml))
    
    def load_topology_from_file(self, path: str) -> None:
        """
        Load a topology YAML file from disk and upload it to the simulator.

        Args:
            path (str): Path to the YAML topology file.
        """
        with open(path, "r", encoding="utf-8") as f:
            yaml_content = f.read()
        self.upload_topology(yaml_content)


    def set_env(self, variable: str, value: Any) -> None:
        """Set an environment variable in the simulator."""
        assert self._async_client is not None, "Client is not connected"
        self._run(self._async_client.set_env(variable, value))

    def send_command(
        self, component: str, command: str, arguments: Optional[Dict[str, Any]] = None
    ) -> None:
        """Send a command to a specific component."""
        assert self._async_client is not None, "Client is not connected"
        self._run(self._async_client.send_command(component, command, arguments))

    # ------------------------------------------------------------------
    # Waiters (blocking)
    # ------------------------------------------------------------------

    def wait_for_status(self, state: str, timeout: Optional[float] = None) -> Dict[str, Any]:
        """Block until simulator reaches a given state (idle/ready/running)."""
        assert self._async_client is not None, "Client is not connected"
        try:
            return self._run(self._async_client.wait_for_status(state, timeout))
        except NestTimeoutError:
            # Fallback: request latest known status
            logger.warning(f"Timeout while waiting for status={state}. Fetching current state...")
            last = self._run(self._async_client.wait_for_type("status", None, None, timeout=2))
            logger.info(f"Last received status: {last}")
            return last

    def wait_for_log(self, level: Optional[str] = None, timeout: Optional[float] = None) -> Dict[str, Any]:
        """Block until a log message arrives (optionally filtered by level)."""
        assert self._async_client is not None, "Client is not connected"
        return self._run(self._async_client.wait_for_log(level, timeout))

    def wait_for_event(
        self, component: Optional[str] = None, event: Optional[str] = None, timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        """Block until a matching event is received."""
        assert self._async_client is not None, "Client is not connected"
        return self._run(self._async_client.wait_for_event(component, event, timeout))

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------
    def __enter__(self):
        """Enable use as a context manager."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        """Ensure clean disconnection on context exit."""
        try:
            self.disconnect()
        except Exception:
            pass

