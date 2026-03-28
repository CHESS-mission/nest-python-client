#!/usr/bin/env python3
"""
fault_injector.py — Python client for the fault_inject TCG plugin.

This module provides:
  • FaultInjectorClient  — low-level JSON socket client
  • InjectionScheduler   — higher-level scheduler that waits for the right
                           instruction-count window and fires injections
  • InjectionResult      — dataclass for structured results
  • SEUCampaign          — runs a sequence of injections and records outcomes

Typical use (manual Phase 1)
-----------------------------
    from fault_injector import FaultInjectorClient, InjectionSpec

    with FaultInjectorClient("/tmp/fault_inject.sock") as fi:
        count = fi.get_count()
        print(f"Current instruction count: {count}")

        # Flip bit 3 of the byte at guest vaddr 0x600d00a8,
        # 2 000 000 instructions from now
        result = fi.inject_mem(addr=0x600d00a8, bit=3, delay=2_000_000)
        print(result)

Typical use (automated Phase 2)
--------------------------------
    campaign = SEUCampaign(
        socket_path="/tmp/fault_inject.sock",
        elf_path=Path("CHESS-FS/build-.../CHESS_Pathfinder0FS"),
        pty_log_path=Path("/tmp/qemu-serial.log"),
    )
    campaign.run_sweep(candidates_only=True, delay=5_000_000)
"""

from __future__ import annotations

import json
import socket
import time
import threading
import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional
import re


# ── GDB Remote Serial Protocol memory writer ─────────────────────────────────

class GdbMemWriter:
    """
    Writes a single byte into the QEMU guest via the GDB Remote Serial Protocol.

    Sequence:
      1. Connect TCP to QEMU's -gdb stub.
      2. Send Ctrl-C (0x03) to halt the guest vCPU.
      3. Send  $M<addr>,1:<hex>#<csum>  to write the byte.
      4. Send  $c#63  to resume the guest.
      5. Disconnect.

    The halt lasts <1 ms under TCG — well below FPrime's health watchdog.
    """

    def __init__(self, host: str = "localhost", port: int = 1234):
        self.host = host
        self.port = port

    # ── GDB packet helpers ────────────────────────────────────────────────────

    @staticmethod
    def _csum(data: str) -> str:
        return f"{sum(data.encode('ascii')) & 0xff:02x}"

    @staticmethod
    def _pkt(data: str) -> bytes:
        return f"${data}#{GdbMemWriter._csum(data)}".encode("ascii")

    # ── Public API ────────────────────────────────────────────────────────────

    @staticmethod
    def _recv_pkt(s: socket.socket, timeout: float = 3.0) -> str:
        """
        Drain buffered data until a complete GDB RSP packet `$data#xx` is found.
        Send `+` ACK and return the inner data string. Returns "" on timeout.
        """
        buf = b""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            s.settimeout(0.1)
            try:
                chunk = s.recv(1024)
                if chunk:
                    buf += chunk
            except socket.timeout:
                pass
            # Parse: skip leading ACK bytes, look for complete packet
            while buf:
                if buf[0:1] in (b"+", b"-"):
                    buf = buf[1:]
                    continue
                if b"$" in buf:
                    si = buf.index(b"$")
                    hi = buf.find(b"#", si)
                    if hi >= 0 and len(buf) >= hi + 3:
                        data = buf[si + 1 : hi].decode("ascii", errors="replace")
                        s.sendall(b"+")  # ACK
                        return data
                break
        return ""

    def write_byte(self, addr: int, value: int) -> bool:
        """
        Halt QEMU, overwrite the byte at *addr* with *value*, then resume.
        Returns True if QEMU acknowledged the write with OK.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5.0)
                s.connect((self.host, self.port))

                # 1. Halt: send Ctrl-C interrupt.
                #    Sleep 0.3 s to let QEMU flush the stop-reply through TCP
                #    before we start draining (avoids a tight-loop race).
                s.sendall(b"\x03")
                time.sleep(0.3)
                self._recv_pkt(s, timeout=1.0)  # consume stop-reply (T02/S02)

                # 2. Write memory: $M<addr>,1:<byte>#<csum>
                data = f"M{addr:x},1:{value:02x}"
                s.sendall(self._pkt(data))
                resp = self._recv_pkt(s, timeout=2.0)
                write_ok = resp == "OK"

                # 3. Resume guest: $c#63
                s.sendall(self._pkt("c"))
                # Don't wait for stop-reply — guest continues on its own.

                return write_ok

        except Exception:
            return False


# ── Low-level client ─────────────────────────────────────────────────────────

class PluginError(RuntimeError):
    pass


@dataclass
class InjectionSpec:
    addr: int              # guest virtual address (byte to flip)
    bit: int               # bit index 0-7 within the byte
    delay: int = 5_000_000 # instructions from *now* to inject


@dataclass
class InjectionResult:
    spec: InjectionSpec
    trigger_insn: int      # absolute insn count when injection fired
    success: bool          # memory write succeeded
    original: int          # original byte value
    flipped: int           # byte value after flip
    elapsed_s: float       # wall time between schedule and confirm
    outcome: str = "unknown"  # set by oracle: CRASH / DETECTED / MASKED / BENIGN

    def summary(self) -> str:
        return (
            f"addr=0x{self.spec.addr:08x} bit={self.spec.bit} "
            f"0x{self.original:02x}→0x{self.flipped:02x} "
            f"ok={self.success} insn={self.trigger_insn:,} "
            f"outcome={self.outcome}"
        )


class FaultInjectorClient:
    """
    Thin wrapper around the plugin's Unix domain socket.

    Each method opens a fresh connection (the plugin serves one request per
    connection, then closes it), so the client is stateless and re-entrant.

    Parameters
    ----------
    socket_path : path to the plugin's Unix control socket
    gdb_port    : TCP port of QEMU's -gdb stub (default 1234).  When set,
                  wait_for_result() will write the flipped byte via GDB after
                  the plugin signals that the trigger fired.  Pass None to
                  disable GDB writes (injection will be logged but not applied).
    gdb_host    : hostname for the GDB stub (default "localhost")
    """

    CONNECT_TIMEOUT = 5.0   # seconds to wait for plugin socket to appear
    RECV_TIMEOUT    = 2.0

    def __init__(self, socket_path: str | Path,
                 gdb_port: int | None = 1234,
                 gdb_host: str = "localhost"):
        self.socket_path = str(socket_path)
        self._gdb = GdbMemWriter(gdb_host, gdb_port) if gdb_port else None

    # ── Context manager ──────────────────────────────────────────────────────

    def __enter__(self):
        self.wait_for_socket()
        return self

    def __exit__(self, *_):
        pass

    # ── Helpers ──────────────────────────────────────────────────────────────

    def wait_for_socket(self, timeout: float = CONNECT_TIMEOUT) -> None:
        """Block until the plugin socket file appears."""
        deadline = time.monotonic() + timeout
        while not Path(self.socket_path).exists():
            if time.monotonic() > deadline:
                raise PluginError(
                    f"Timed out waiting for plugin socket: {self.socket_path}"
                )
            time.sleep(0.1)

    def _request(self, payload: dict) -> dict:
        """Send a JSON request and return the parsed JSON response."""
        raw = json.dumps(payload, separators=(",", ":")) + "\n"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(self.RECV_TIMEOUT)
            s.connect(self.socket_path)
            s.sendall(raw.encode())
            resp_bytes = b""
            while True:
                try:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    resp_bytes += chunk
                    if resp_bytes.endswith(b"\n"):
                        break
                except socket.timeout:
                    break

        resp = json.loads(resp_bytes.decode().strip())
        if resp.get("status") != "ok":
            raise PluginError(f"Plugin error: {resp.get('msg', resp)}")
        return resp

    # ── API ──────────────────────────────────────────────────────────────────

    def get_count(self) -> int:
        """Return the current instruction count from the plugin."""
        resp = self._request({"cmd": "get_count"})
        return int(resp["insn_count"])

    def is_pending(self) -> bool:
        """Return True if an injection is scheduled but not yet fired."""
        resp = self._request({"cmd": "get_count"})
        return bool(resp.get("pending", False))

    def inject_mem(self, addr: int, bit: int, delay: int) -> int:
        """
        Schedule a bit-flip injection.

        Parameters
        ----------
        addr  : guest virtual address of the byte to flip
        bit   : bit index (0 = LSB, 7 = MSB) within that byte
        delay : instructions from *now* after which the flip occurs

        Returns
        -------
        trigger_insn : absolute instruction count at which the flip will occur
        """
        resp = self._request({
            "cmd":   "inject_mem",
            "addr":  addr,
            "bit":   bit,
            "delay": delay,
        })
        return int(resp["trigger_insn"])

    def clear(self) -> None:
        """Cancel any pending injection."""
        self._request({"cmd": "clear"})

    def last_result(self) -> dict | None:
        """
        Return the last injection result dict, or None if no injection has
        occurred yet.
        """
        resp = self._request({"cmd": "last_result"})
        if not resp.get("injected"):
            return None
        return resp

    def wait_for_result(self, timeout: float = 30.0, poll_interval: float = 0.2,
                        trigger_insn: int | None = None) -> dict | None:
        """
        Poll last_result() until a *fresh* injection result appears or timeout expires.

        ``trigger_insn`` should be the value returned by inject_mem().  Any
        cached result whose insn_count < trigger_insn is treated as stale and
        ignored, preventing the previous injection's result from being returned.

        When the plugin reports a trigger and a GdbMemWriter is configured, the
        flipped byte is written to guest memory via the GDB stub.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r = self.last_result()
            if r is not None:
                # Skip stale results from a previous injection
                if trigger_insn is not None and int(r.get("insn_count", 0)) < trigger_insn:
                    time.sleep(poll_interval)
                    continue
                # Plugin signalled trigger — perform GDB write if available
                if not r.get("success") and self._gdb is not None:
                    addr    = int(r["addr"])
                    flipped = int(r["flipped"])
                    ok = self._gdb.write_byte(addr, flipped)
                    r["success"] = ok
                    r["gdb_write"] = True
                return r
            time.sleep(poll_interval)
        return None


# ── Oracle: monitor PTY log for crash / detection signals ────────────────────

class PtyOracle:
    """
    Tail the QEMU serial PTY log and classify how the FS responded to a fault.

    Outcomes
    --------
    CRASH     — guest/process died: kernel panic, SIGSEGV, FPrime Assert, or
                the FS stopped producing EVENT lines entirely (liveness timeout).
    DETECTED  — FPrime's Svc::Health or any component logged a WARNING/ERROR/
                FATAL-severity EVR (generic, works for any component).
    MASKED    — FS kept running and no anomaly was logged.

    Design rationale
    ----------------
    Patterns are component-agnostic.  Three independent signals are used:

    1. OS/process crash strings (kernel panic, segfault, abort, …).
    2. FPrime-level crash: "Assert:" in the output (FW_ASSERT fires before exit).
    3. FPrime EVR severity: any EVR line that carries WARNING / ERROR / FATAL
       in its severity field — covers Svc::Health ping warnings AND any future
       component that reports a fault through FPrime's event system.
    4. Liveness: if no "EVENT:" line appears for >LIVENESS_TIMEOUT_S seconds
       the FS is considered silent/crashed.
    """

    # ── 1. OS / process-level crash ──────────────────────────────────────────
    _OS_CRASH_RE = re.compile(
        r"Kernel panic|Oops:|segfault|SIGSEGV|illegal instruction"
        r"|Aborted|core dumped|BUG: Bad page",
        re.IGNORECASE,
    )

    # ── 2. FPrime process-level abort (FW_ASSERT prints "Assert: <file>:<line>")
    _FPRIME_ASSERT_RE = re.compile(r'^Assert:\s', re.MULTILINE)

    # ── 3. FPrime EVR with WARNING / ERROR / FATAL severity
    #    FPrime log format: "EVENT: (seq) (time) SEVERITY: (component) EVR_NAME"
    #    We match the severity field generically — works for every component.
    _FPRIME_FAULT_RE = re.compile(
        r"(WARNING_HI|WARNING_LO|ERROR|FATAL|ACTIVITY_HI.*fault"
        r"|HLTH_PING_WARN|HLTH_PING_LATE|HLTH_PING_WRONG_KEY)",
        re.IGNORECASE,
    )

    # How long (seconds) without any EVENT: line before we declare the FS dead
    LIVENESS_TIMEOUT_S: float = 2.0

    def __init__(self, pty_log_path: Path):
        self.pty_log_path = pty_log_path
        self._lines: list[str] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_event_ts: float = time.monotonic()  # tracks FS liveness

    def start(self) -> None:
        """Start tailing the log in a background thread."""
        self._stop.clear()
        self._last_event_ts = time.monotonic()
        self._thread = threading.Thread(target=self._tail, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _tail(self) -> None:
        try:
            with self.pty_log_path.open("r", errors="replace") as f:
                f.seek(0, 2)  # seek to end — only watch new lines
                while not self._stop.is_set():
                    line = f.readline()
                    if line:
                        stripped = line.rstrip()
                        with self._lock:
                            self._lines.append(stripped)
                            if "EVENT:" in stripped:
                                self._last_event_ts = time.monotonic()
                    else:
                        time.sleep(0.05)
        except FileNotFoundError:
            pass

    def recent_lines(self, n: int = 100) -> list[str]:
        with self._lock:
            return list(self._lines[-n:])

    def drain(self) -> None:
        """Discard all accumulated log lines and reset the liveness clock.
        Call before scheduling each injection so classify() only sees events
        that occurred AFTER this point — prevents stale events from a previous
        injection bleeding into the next verdict."""
        with self._lock:
            self._lines.clear()
            self._last_event_ts = time.monotonic()

    def classify(self, observation_window_s: float = 8.0) -> dict:
        """
        Observe the PTY log for `observation_window_s` seconds, then return::

            {
                "outcome":  "CRASH" | "DETECTED" | "MASKED",
                "evidence": <line / reason that triggered the verdict>,
                "last_events": [last ≤5 FPrime EVENT lines seen],
            }

        ``evidence`` identifies the specific fault signal.
        ``last_events`` shows the most recent FS telemetry — useful both as
        proof-of-life after MASKED and as last-known-good state before a crash.
        """
        deadline = time.monotonic() + observation_window_s
        seen_ids: set[int] = set()
        crashed = detected = False
        evidence = ""

        # Reset liveness clock at the start of the observation window
        with self._lock:
            self._last_event_ts = time.monotonic()

        while time.monotonic() < deadline:
            with self._lock:
                snap = list(self._lines)
                last_event_age = time.monotonic() - self._last_event_ts

            for idx, line in enumerate(snap):
                if idx in seen_ids:
                    continue
                seen_ids.add(idx)

                if not crashed:
                    if self._OS_CRASH_RE.search(line):
                        crashed = True; evidence = f"[OS] {line}"
                    elif self._FPRIME_ASSERT_RE.search(line):
                        crashed = True; evidence = f"[Assert] {line}"

                if not detected and not crashed:
                    if self._FPRIME_FAULT_RE.search(line):
                        detected = True; evidence = f"[EVR] {line}"

            # Liveness check: FS silent for too long → crash/hang
            if not crashed and last_event_age > self.LIVENESS_TIMEOUT_S:
                crashed = True
                evidence = (f"[liveness] No EVENT: line for "
                            f"{last_event_age:.1f}s — FS appears dead")
                break

            if crashed:
                break

            time.sleep(0.1)

        last_events = [l for l in self.recent_lines(60) if "EVENT:" in l][-5:]
        outcome = "CRASH" if crashed else ("DETECTED" if detected else "MASKED")
        return {"outcome": outcome, "evidence": evidence,
                "last_events": last_events}


# ── CHESS restart helper ──────────────────────────────────────────────────────

def restart_chess_in_qemu(pty_log: Path, timeout: float = 120.0) -> bool:
    """
    Restart CHESS inside the running QEMU VM via the PTY device.

    Writes a shell command to /tmp/qemu-serial-pty that kills any residual
    CHESS process and relaunches it.  Then calls PtyOracle._wait_for_chess
    (reimplemented inline) to confirm the binary is live.

    Safe for BSS-target injections (anonymous memory is fresh per process).
    Text-segment injections corrupt the Linux page cache — the restarted
    process loads the same corrupted page.
    """
    import os, select as _select

    CHESS_BINARY = "/CHESS/CHESS_Pathfinder0FS"
    pty_dev = Path("/tmp/qemu-serial-pty")

    try:
        with pty_dev.open("r+b", buffering=0) as pty:
            pty.write(b"\n")        # wake shell
            time.sleep(0.3)
            pty.write(
                f"killall {CHESS_BINARY.split('/')[-1]} 2>/dev/null; "
                f"ulimit -c 0; {CHESS_BINARY} \n".encode()
            )
        print("  Sent PTY restart command.", flush=True)
    except OSError as e:
        print(f"  WARNING: Could not write to PTY ({e}); skipping restart.",
              flush=True)
        return False

    # Re-use the same keyword scan that PtyOracle uses
    _READY_KEYWORDS = [
        "CHESS_Pathfinder0FS",
        "OpCodeRegistered",
        "Starting HealthImpl",
        "Registered with",
        "all components ready",
        "rate group",
        "SENSOR_POLL_CYCLE",
    ]

    print(f"  Waiting for CHESS ready (watching {pty_log})…", flush=True)
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
                    if any(kw in decoded for kw in _READY_KEYWORDS):
                        print(f"  CHESS ready: {decoded.strip()}", flush=True)
                        return True
        except (FileNotFoundError, OSError):
            time.sleep(0.5)
    print("  WARNING: timed out waiting for CHESS restart.", flush=True)
    return False


# ── Higher-level campaign runner ─────────────────────────────────────────────

@dataclass
class CampaignConfig:
    socket_path: Path
    elf_path: Path
    pty_log_path: Path
    delay_insn: int          = 5_000_000   # instructions before each injection
    observation_window_s: float = 15.0     # seconds to wait for oracle verdict
    candidates_only: bool    = True        # only inject into FPrime variables
    filter_re: str | None    = None        # additional symbol name regex filter
    results_path: Path       = Path("/tmp/seu_results.jsonl")


class SEUCampaign:
    """
    Orchestrates a sequence of SEU injections:

      1. Read ELF symbol table → build list of injection targets
      2. For each target: schedule → wait for firing → classify outcome
      3. Append result to JSONL file for analysis

    Phase 1 usage (a few manual targets):
    ----------------------------------------
        campaign = SEUCampaign(cfg)
        campaign.run_targets([
            InjectionSpec(addr=0x600d00a8, bit=3, delay=5_000_000),
            InjectionSpec(addr=0x600d00b0, bit=7, delay=5_000_000),
        ])

    Phase 2 usage (exhaustive sweep of all ELF candidates):
    --------------------------------------------------------
        campaign.run_sweep()
    """

    def __init__(self, cfg: CampaignConfig):
        self.cfg = cfg
        self._results: list[InjectionResult] = []

    # ── Core injection loop ──────────────────────────────────────────────────

    def _run_one(self,
                 client: FaultInjectorClient,
                 oracle: PtyOracle,
                 spec: InjectionSpec) -> InjectionResult:

        t0 = time.monotonic()
        trigger = client.inject_mem(addr=spec.addr, bit=spec.bit, delay=spec.delay)
        print(f"  Scheduled: addr=0x{spec.addr:08x} bit={spec.bit} "
              f"trigger_insn={trigger:,}")

        # Wait for the injection to fire — pass trigger_insn to skip stale results
        plugin_resp = client.wait_for_result(
            timeout=self.cfg.observation_window_s * 0.5,
            trigger_insn=trigger,
        )
        elapsed = time.monotonic() - t0

        if plugin_resp is None:
            print("  WARNING: No injection result received (timed out)")
            return InjectionResult(
                spec=spec,
                trigger_insn=trigger,
                success=False,
                original=0,
                flipped=0,
                elapsed_s=elapsed,
                outcome="NO_INJECT",
            )

        success  = bool(plugin_resp.get("success", False))
        original = int(plugin_resp.get("original", 0))
        flipped  = int(plugin_resp.get("flipped",  0))

        # Classify FPrime's response
        verdict = oracle.classify(self.cfg.observation_window_s * 0.5)

        result = InjectionResult(
            spec=spec,
            trigger_insn=trigger,
            success=success,
            original=original,
            flipped=flipped,
            elapsed_s=elapsed,
            outcome=verdict["outcome"],
        )
        return result

    # ── Public API ───────────────────────────────────────────────────────────

    def run_targets(self, specs: Iterable[InjectionSpec],
                    reset_between: bool = True) -> list[InjectionResult]:
        """Run a manually specified list of injection specs.

        reset_between=True (default): restart CHESS after every injection so
        each test starts from a clean state.  The oracle buffer is drained
        before each injection to prevent stale events from the previous test
        or the boot sequence from polluting the verdict.
        """
        oracle = PtyOracle(self.cfg.pty_log_path)
        oracle.start()

        specs = list(specs)
        results = []
        try:
            with FaultInjectorClient(self.cfg.socket_path) as client:
                for i, spec in enumerate(specs):
                    # Drain oracle before each injection — only fresh events count
                    oracle.drain()

                    print(f"\n[{i+1}/{len(specs)}] addr=0x{spec.addr:08x} "
                          f" bit={spec.bit}  delay={spec.delay:,} insns")

                    result = self._run_one(client, oracle, spec)
                    results.append(result)
                    self._append_result(result)
                    print(f"  → {result.summary()}")

                    # Restart CHESS for independence (skip after last injection)
                    if reset_between and i < len(specs) - 1:
                        print("  Resetting CHESS for next injection…", flush=True)
                        restarted = restart_chess_in_qemu(
                            self.cfg.pty_log_path, timeout=120.0)
                        if not restarted:
                            print("  WARNING: FS did not restart; continuing.",
                                  flush=True)
                        # Drain boot messages so they don't count as evidence
                        oracle.drain()
                    elif result.outcome == "CRASH" and not reset_between:
                        restarted = restart_chess_in_qemu(
                            self.cfg.pty_log_path, timeout=120.0)
                        oracle.drain()
        finally:
            oracle.stop()

        self._results.extend(results)
        return results

    def run_sweep(self,
                  max_targets: int | None = None,
                  on_result: Callable[[InjectionResult], None] | None = None
                  ) -> list[InjectionResult]:
        """
        Phase 2: exhaustive sweep.  Reads the ELF, builds every possible
        bit-flip target in FPrime state variables, and runs them sequentially.
        """
        from nest_client.seu.elf_analyzer import get_injection_targets

        filter_re = (re.compile(self.cfg.filter_re)
                     if self.cfg.filter_re else None)

        targets = get_injection_targets(
            self.cfg.elf_path,
            candidates_only=self.cfg.candidates_only,
            filter_re=filter_re,
        )
        print(f"Sweep: {len(targets)} bit-flip targets in ELF "
              f"({'candidates only' if self.cfg.candidates_only else 'all symbols'})")

        if max_targets:
            targets = targets[:max_targets]
            print(f"  (limited to first {max_targets})")

        specs = [
            InjectionSpec(addr=t["addr"], bit=t["bit"],
                          delay=self.cfg.delay_insn)
            for t in targets
        ]
        results = self.run_targets(specs)

        if on_result:
            for r in results:
                on_result(r)

        return results

    # ── Result persistence ───────────────────────────────────────────────────

    def _append_result(self, result: InjectionResult) -> None:
        record = {
            "addr":         f"0x{result.spec.addr:08x}",
            "bit":          result.spec.bit,
            "trigger_insn": result.trigger_insn,
            "success":      result.success,
            "original":     f"0x{result.original:02x}",
            "flipped":      f"0x{result.flipped:02x}",
            "elapsed_s":    round(result.elapsed_s, 3),
            "outcome":      result.outcome,
        }
        with self.cfg.results_path.open("a") as f:
            f.write(json.dumps(record) + "\n")

    def print_summary(self) -> None:
        from collections import Counter
        counts = Counter(r.outcome for r in self._results)
        total  = len(self._results)
        print("\n── SEU Campaign Summary ──────────────────────────────")
        print(f"  Total injections : {total}")
        for outcome, n in sorted(counts.items()):
            pct = 100 * n / total if total else 0
            print(f"  {outcome:<12} : {n:4d}  ({pct:.1f}%)")
        print(f"  Results file     : {self.cfg.results_path}")
        print("─────────────────────────────────────────────────────")


# ── CLI: quick manual injection ───────────────────────────────────────────────

def _cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Schedule a single SEU bit-flip via the fault_inject plugin."
    )
    parser.add_argument("--socket", default="/tmp/fault_inject.sock",
                        help="Path to plugin control socket")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # inject
    p_inj = sub.add_parser("inject", help="Schedule a bit-flip")
    p_inj.add_argument("--addr", required=True,
                       help="Guest vaddr (hex or dec)")
    p_inj.add_argument("--bit", type=int, required=True,
                       help="Bit index 0-7")
    p_inj.add_argument("--delay", type=int, default=5_000_000,
                       help="Instructions from now (default 5M)")

    # count
    sub.add_parser("count", help="Print current instruction count")

    # result
    sub.add_parser("result", help="Print last injection result")

    # clear
    sub.add_parser("clear", help="Cancel pending injection")

    args = parser.parse_args()

    with FaultInjectorClient(args.socket) as fi:
        if args.cmd == "count":
            cnt = fi.get_count()
            print(f"insn_count = {cnt:,}")

        elif args.cmd == "inject":
            addr = int(args.addr, 0)
            trigger = fi.inject_mem(addr=addr, bit=args.bit, delay=args.delay)
            print(f"Scheduled: addr=0x{addr:08x} bit={args.bit} "
                  f"trigger_insn={trigger:,}")
            print("Waiting for injection result…")
            r = fi.wait_for_result(timeout=60.0, trigger_insn=trigger)
            if r:
                print(json.dumps(r, indent=2))
            else:
                print("Timed out waiting for result.")

        elif args.cmd == "result":
            r = fi.last_result()
            print(json.dumps(r, indent=2) if r else "No result yet.")

        elif args.cmd == "clear":
            fi.clear()
            print("Cleared.")


if __name__ == "__main__":
    _cli()
