from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from rich.console import Console
from rich.live import Live
from rich.logging import RichHandler
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text


class Phase(str, Enum):
    PENDING       = "pending"
    LAUNCHING     = "launching"
    CONNECTING    = "connecting"
    RUNNING       = "running"
    DONE          = "done"
    FAILED        = "failed"
    CRASHED       = "crashed"
    CRASHED_SETUP = "crashed_setup"


_TERMINAL_PHASES = {Phase.DONE, Phase.FAILED, Phase.CRASHED, Phase.CRASHED_SETUP}


@dataclass
class InstanceInfo:
    phase: Phase = Phase.PENDING
    start_time: float | None = None
    end_time: float | None = None
    event_count: int = 0
    server_state: str = "—"
    passed: int | None = None
    failed: int | None = None
    error_msg: str = ""
    simulation_started: bool = False


_SPINNER_FRAMES = Spinner("dots").frames

_PHASE_STYLE = {
    Phase.PENDING:       ("dim", "PENDING"),
    Phase.LAUNCHING:     ("yellow", "LAUNCHING"),
    Phase.CONNECTING:    ("yellow", "CONNECTING"),
    Phase.RUNNING:       ("cyan", "RUNNING"),
    Phase.DONE:          ("green", "DONE"),
    Phase.FAILED:        ("red", "FAILED"),
    Phase.CRASHED:       ("red", "CRASHED"),
    Phase.CRASHED_SETUP: ("yellow", "CRASHED SETUP"),
}


class RunDashboard:
    def __init__(self, n: int, title: str = ""):
        self._n = n
        self._title = title
        self._lock = threading.Lock()
        self._instances: list[InstanceInfo] = [InstanceInfo() for _ in range(n)]
        self._spinner_frame = 0
        self._console = Console(highlight=False)
        self._live = Live(
            self._render(),
            console=self._console,
            refresh_per_second=8,
            transient=False,
        )
        self._spinner_thread: threading.Thread | None = None
        self._stop_spinner = threading.Event()
        self._saved_handlers: list[logging.Handler] = []
        self._rich_handler: RichHandler | None = None

    def __enter__(self) -> RunDashboard:
        self._live.start(refresh=True)
        self._stop_spinner.clear()
        self._spinner_thread = threading.Thread(target=self._spin, daemon=True)
        self._spinner_thread.start()
        self._install_log_handler()
        return self

    def __exit__(self, *_) -> None:
        self._stop_spinner.set()
        if self._spinner_thread:
            self._spinner_thread.join(timeout=1.0)
        self._restore_log_handlers()
        self._live.update(self._render())
        self._live.stop()

    def _install_log_handler(self) -> None:
        root = logging.getLogger()
        self._saved_handlers = root.handlers[:]
        for h in self._saved_handlers:
            root.removeHandler(h)
        self._rich_handler = RichHandler(
            console=self._console,
            show_path=False,
            markup=False,
            rich_tracebacks=True,
        )
        self._rich_handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%H:%M:%S]"))
        self._rich_handler.setLevel(logging.CRITICAL + 1)  # suppress all terminal logging
        root.addHandler(self._rich_handler)

    def _restore_log_handlers(self) -> None:
        root = logging.getLogger()
        if self._rich_handler is not None:
            root.removeHandler(self._rich_handler)
            self._rich_handler = None
        for h in self._saved_handlers:
            root.addHandler(h)
        self._saved_handlers = []

    def _spin(self) -> None:
        while not self._stop_spinner.is_set():
            with self._lock:
                self._spinner_frame = (self._spinner_frame + 1) % len(_SPINNER_FRAMES)
            self._live.update(self._render())
            self._stop_spinner.wait(0.125)

    def set_simulation_started(self, index: int) -> None:
        with self._lock:
            self._instances[index].simulation_started = True

    def update(self, index: int, phase: Phase, **kwargs) -> None:
        with self._lock:
            info = self._instances[index]
            _crash_phases = (Phase.CRASHED, Phase.CRASHED_SETUP)
            # Crash state is terminal: preserve phase and error message as-is.
            if info.phase in _crash_phases and phase == Phase.DONE:
                self._live.update(self._render())
                return
            info.phase = phase
            if phase == Phase.RUNNING and info.start_time is None:
                info.start_time = time.monotonic()
            if phase in _TERMINAL_PHASES and info.end_time is None:
                info.end_time = time.monotonic()
            for k, v in kwargs.items():
                setattr(info, k, v)
        self._live.update(self._render())

    def on_server_msg(self, index: int, msg: dict) -> None:
        with self._lock:
            info = self._instances[index]
            t = msg.get("type")
            if t == "event" and info.phase not in (Phase.CRASHED, Phase.CRASHED_SETUP):
                info.event_count += 1
            elif t == "status":
                info.server_state = msg.get("state", "?")
            elif t == "error":
                info.phase = Phase.CRASHED if info.simulation_started else Phase.CRASHED_SETUP
                info.error_msg = str(msg.get("message", "server error"))
                if info.end_time is None:
                    info.end_time = time.monotonic()
        self._live.update(self._render())

    def _render(self) -> Table:
        table = Table(
            title=self._title,
            show_header=True,
            header_style="bold",
            border_style="dim",
            expand=False,
        )
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Status", width=16)
        table.add_column("Elapsed", width=10, justify="right")
        table.add_column("Events", width=8, justify="right")
        table.add_column("Result", width=20, overflow="fold")

        for i, info in enumerate(self._instances):
            style, label = _PHASE_STYLE[info.phase]

            # Status cell
            if info.phase == Phase.RUNNING:
                frame = _SPINNER_FRAMES[self._spinner_frame]
                status_text = Text(f"{frame} {label}", style=style)
            elif info.phase == Phase.DONE:
                status_text = Text(f"✓ {label}", style=style)
            elif info.phase in (Phase.FAILED, Phase.CRASHED, Phase.CRASHED_SETUP):
                status_text = Text(f"✗ {label}", style=style)
            else:
                status_text = Text(label, style=style)

            # Elapsed — frozen once a terminal phase is reached
            if info.start_time is not None:
                stop = info.end_time if info.end_time is not None else time.monotonic()
                elapsed_str = f"{stop - info.start_time:.1f}s"
            else:
                elapsed_str = "—"

            # Events
            events_str = str(info.event_count) if info.event_count > 0 else "—"

            # Result
            _crash_phases = (Phase.CRASHED, Phase.CRASHED_SETUP)
            if info.phase in (Phase.DONE,) + _crash_phases and info.passed is not None:
                total = (info.passed or 0) + (info.failed or 0)
                if info.failed:
                    result_text = Text(f"{info.passed}/{total} passed", style="red")
                else:
                    result_text = Text(f"{info.passed}/{total} passed", style="green")
            elif info.phase in (Phase.FAILED,) + _crash_phases and info.error_msg:
                result_text = Text(info.error_msg, style="red")
            else:
                result_text = Text("—", style="dim")

            table.add_row(
                str(i),
                status_text,
                elapsed_str,
                events_str,
                result_text,
            )

        return table
