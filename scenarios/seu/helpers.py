"""Shared utility functions used by all phase runners."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Union

import numpy as np

from nest_client.seu.injector import (
    CHESS_READY_KEYWORDS,
    FaultInjectorClient,
    PtyOracle,
    restart_chess_in_qemu,
)
from nest_client.client import NestClient
from nest_client.types import EnvVarType

from .config import _docker_mode, SOCK_PATH, PTY_LOG, NEST_URL


# Readiness helpers

def wait_for_chess_ready(pty_log: Union[Path, tuple], timeout: float = 120.0) -> bool:
    """Wait until the CHESS binary logs a recognised startup keyword."""
    print(f"Waiting for CHESS binary to be ready (watching {pty_log})…")

    if isinstance(pty_log, tuple):
        oracle = PtyOracle(pty_log)
        oracle.start()
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                for line in oracle.recent_lines(200):
                    if any(kw in line for kw in CHESS_READY_KEYWORDS):
                        print(f"  -> CHESS ready: {line.strip()}")
                        return True
                time.sleep(0.2)
        finally:
            oracle.stop()
        print("WARNING: Timed out waiting for CHESS to be ready. Proceeding anyway.")
        return False

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            is_binary = pty_log.suffix != ".log"
            with pty_log.open("rb" if is_binary else "r",
                              **({} if is_binary else {"errors": "replace"})) as f:
                while time.monotonic() < deadline:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    decoded = line if isinstance(line, str) else line.decode(errors="replace")
                    if any(kw in decoded for kw in CHESS_READY_KEYWORDS):
                        print(f"  -> CHESS ready: {decoded.strip()}")
                        return True
        except (FileNotFoundError, OSError):
            time.sleep(0.5)

    print("WARNING: Timed out waiting for CHESS to be ready. Proceeding anyway.")
    return False


def restart_chess(pty_log: Union[Path, tuple, None], timeout: float = 120.0) -> bool:
    """Restart CHESS via the PTY. No-op in Docker mode (Phoenix handles it)."""
    if _docker_mode or isinstance(pty_log, tuple):
        print("  Docker mode: Phoenix handles restart autonomously.", flush=True)
        return True
    return restart_chess_in_qemu(pty_log, timeout=timeout)


def wait_for_cpu_b_takeover(pty_log_b: Union[Path, tuple, None],
                             timeout: float = 60.0) -> float | None:
    """Watch CPU_B's log for FPrime startup, return elapsed seconds or None."""
    if pty_log_b is None:
        return None

    print(f"  Watching CPU_B log for takeover: {pty_log_b}", flush=True)
    t0 = time.monotonic()

    if isinstance(pty_log_b, tuple):
        oracle = PtyOracle(pty_log_b)
        oracle.start()
        deadline = t0 + timeout
        try:
            while time.monotonic() < deadline:
                for line in oracle.recent_lines(200):
                    if any(kw in line for kw in CHESS_READY_KEYWORDS):
                        elapsed = time.monotonic() - t0
                        print(f"  CPU_B active after {elapsed:.1f}s: {line.strip()}", flush=True)
                        return elapsed
                time.sleep(0.2)
        finally:
            oracle.stop()
        print(f"  CPU_B did not take over within {timeout:.0f}s.", flush=True)
        return None

    deadline = t0 + timeout
    while time.monotonic() < deadline:
        try:
            with pty_log_b.open("r", errors="replace") as f:
                while time.monotonic() < deadline:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    if any(kw in line for kw in CHESS_READY_KEYWORDS):
                        elapsed = time.monotonic() - t0
                        print(f"  CPU_B active after {elapsed:.1f}s: {line.strip()}", flush=True)
                        return elapsed
        except (FileNotFoundError, OSError):
            time.sleep(0.5)

    print(f"  CPU_B did not take over within {timeout:.0f}s.", flush=True)
    return None


# Environment setup

def set_nominal_environment(nest_url: str = NEST_URL) -> None:
    """Push nominal sensor env vars to NEST before starting injections."""
    MAG_SENSITIVITY = 16384.0
    MAG_OFFSET      = 131072.0
    b = np.array([
        MAG_OFFSET + MAG_SENSITIVITY * 0.3,
        MAG_OFFSET + MAG_SENSITIVITY * 0.2,
        MAG_OFFSET + MAG_SENSITIVITY * 0.1,
    ])
    print("Setting nominal sensor environment…")
    try:
        with NestClient(url=nest_url) as client:
            client.set_env("temp",    EnvVarType.FLOAT, 35.0)
            client.set_env("accel",   EnvVarType.VEC3,  np.array([0.5, 0.5, 9.8]))
            client.set_env("omega",   EnvVarType.VEC3,  np.array([0.1, 0.2, 0.3]))
            client.set_env("B_field", EnvVarType.VEC3,  b)
        print(f"  temp=35.0  accel=[0.5,0.5,9.8]  omega=[0.1,0.2,0.3]  "
              f"B_field=[{b[0]:.0f},{b[1]:.0f},{b[2]:.0f}]  ✓")
    except Exception as exc:
        print(f"  WARNING: could not set env vars ({exc}). "
              "Sensor readings may be all-zero results will be unreliable.")


# Display

def print_banner(title: str) -> None:
    w = 70
    print("\n" + "─" * w)
    print(f"  {title}")
    print("─" * w)


# Liveness / classification

def _insn_delta(window_s: float) -> int:
    """Open a plugin connection, sleep window_s seconds, return instruction count delta."""
    with FaultInjectorClient(SOCK_PATH) as fi:
        c0 = fi.get_count()
        time.sleep(window_s)
        return fi.get_count() - c0


def _classify(fi, oracle, window_s: float) -> dict:
    """Classify an injection outcome using instruction-count (Docker) or oracle (local)."""
    if _docker_mode:
        delta = fi.get_count()
        time.sleep(window_s)
        delta = fi.get_count() - delta
        alive = delta > 1_000_000
        return {
            "outcome":     "MASKED" if alive else "CRASH",
            "evidence":    f"insn delta={delta:,} ({'alive' if alive else 'halted'})",
            "last_events": [],
        }
    return oracle.classify(observation_window_s=window_s)
