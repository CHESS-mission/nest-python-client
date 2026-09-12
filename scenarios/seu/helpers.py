"""Shared utility functions used by all phase runners."""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Union

import numpy as np

from nest_client.seu.injector import (
    CHESS_READY_KEYWORDS,
    FaultInjectorClient,
    GdbMemWriter,
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


# Beacon readiness (shared by --ci, --sweep, --code, --ci-debug)

_PAYLOAD_RE = re.compile(r"PACKET_SENT\s*:\s*Packet sent with payload\s+(\d+)")
# PACKET_SENT lines carry a kernel timestamp ("[   74.790939] ... PACKET_SENT ...")
# from /dev/kmsg that advances whenever CHESS emits a beacon, regardless of the
# payload VALUE.  Older builds beaconed an integer counter; newer builds beacon a
# float sensor reading (e.g. "payload -0.125000"), which breaks payload-counter
# liveness.  Keying on the timestamp is format-agnostic and works for both.
_BEACON_TS_RE = re.compile(r"\[\s*(\d+\.\d+)\].*PACKET_SENT")


def wait_for_beacon(oracle: PtyOracle, timeout_s: float = 120.0,
                    window_s: float = 5.0, min_advance: int = 2) -> bool:
    """Block until the PACKET_SENT heartbeat is *actively advancing*.

    Counting EVENT: lines in the buffer passes on stale boot-diagnostic events
    even while the FS is quiet; a *fresh* PACKET_SENT line (its kernel timestamp
    advancing within the window) proves CHESS is emitting now.  Gating golden
    capture / the Layer-5 build / injection arming on this avoids them running
    against a still-booting, quiet FS.

    Returns True once the beacon's timestamp advances by >= ~min_advance guest
    seconds within window_s (payload-format agnostic: int counter or float value).
    """
    def _last_beacon_ts():
        vals = [float(m.group(1)) for l in oracle.recent_lines(400)
                if l and (m := _BEACON_TS_RE.search(l))]
        return vals[-1] if vals else None

    need = max(1.0, float(min_advance) * 0.75)  # ~min_advance beacons at ~1 Hz
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        t0 = _last_beacon_ts()
        time.sleep(window_s)
        t1 = _last_beacon_ts()
        if t0 is not None and t1 is not None and (t1 - t0) >= need:
            return True
    return False


def ensure_beacon(oracle: PtyOracle, gdb_host: str | None,
                  initial_wait_s: float = 30.0,
                  post_reset_wait_s: float = 120.0) -> bool:
    """Guarantee CHESS is beaconing; reset a stuck no_phoenix boot to recover.

    The initial boot is unreliable - CHESS sometimes never reaches steady state
    (Health uninitialised, no PACKET_SENT) and, with Phoenix masked, cannot self-
    recover.  A system_reset reliably brings it up (the same recovery the per-
    injection path uses).  Probe briefly; if stuck, reset once and wait again.
    """
    if wait_for_beacon(oracle, timeout_s=initial_wait_s):
        return True
    print("  Beacon stuck at boot — issuing system_reset to recover…", flush=True)
    if gdb_host:
        try:
            GdbMemWriter(host=gdb_host, port=1234).system_reset()
        except Exception as _e:
            print(f"  WARNING: recovery system_reset failed ({_e})", flush=True)
    oracle.drain()
    return wait_for_beacon(oracle, timeout_s=post_reset_wait_s)


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
