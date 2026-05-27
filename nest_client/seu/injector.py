#!/usr/bin/env python3
"""
fault_injector.py Python client for the fault_inject TCG plugin.

This module provides:
  - FaultInjectorClient   low-level JSON socket client
  - InjectionScheduler    higher-level scheduler that waits for the right
                          instruction-count window and fires injections
  - InjectionResult       dataclass for structured results
  - SEUCampaign           runs a sequence of injections and records outcomes

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
import os
import re
import socket
import struct
import time
import threading
import dataclasses
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional, Tuple, Union


CHESS_READY_KEYWORDS: list[str] = [
    "CHESS_Pathfinder0FS", "OpCodeRegistered", "Starting HealthImpl",
    "Registered with", "all components ready", "rate group", "SENSOR_POLL_CYCLE",
    "EVENT:",  # steady-state F' telemetry - proof CHESS is alive after boot
]

# GDB Remote Serial Protocol memory writer

class GdbMemWriter:
    """
    Writes a single byte into the QEMU guest via the GDB Remote Serial Protocol.

    Sequence:
      1. Connect TCP to QEMU's -gdb stub.
      2. Send Ctrl-C (0x03) to halt the guest vCPU.
      3. Send  $M<addr>,1:<hex>#<csum>  to write the byte.
      4. Send  $c#63  to resume the guest.
      5. Disconnect.

    The halt lasts <1 ms under TCG well below FPrime's health watchdog.
    """

    def __init__(self, host: str = "localhost", port: int = 1234):
        self.host = host
        self.port = port

    # GDB packet helpers

    @staticmethod
    def _csum(data: str) -> str:
        return f"{sum(data.encode('ascii')) & 0xff:02x}"

    @staticmethod
    def _pkt(data: str) -> bytes:
        return f"${data}#{GdbMemWriter._csum(data)}".encode("ascii")

    # Session context manager

    @contextmanager
    def _session(self):
        """Connect to GDB stub, halt the vCPU, yield (socket, stop_reply).

        The stop_reply is the T/S packet from QEMU after Ctrl-C; it contains
        the current PC and is needed by resume_cpu to clear stale breakpoints.
        Methods that don't need it can unpack as ``with self._session() as (s, _)``.
        Callers are responsible for sending ``$c`` to resume before the context
        exits.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect((self.host, self.port))
            s.sendall(b"\x03")
            time.sleep(0.3)
            stop_reply = self._recv_pkt(s, timeout=1.0)
            yield s, stop_reply

    # Public API

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

    _SNAPSHOT_TIMEOUT = 60.0  # savevm/loadvm on a 1 GB VM can take ~10-30s

    def monitor_command(self, cmd: str, timeout: float = 3.0) -> str:
        """
        Send a QEMU human-monitor command via GDB RSP qRcmd passthrough.

        Returns the response string (stripped of leading 'O' output packets).
        Useful for physical-memory writes: ``writel PHYS_ADDR VALUE``.
        Use a larger ``timeout`` for slow commands like savevm/loadvm.
        """
        try:
            with self._session() as (s, _):
                hex_cmd = cmd.encode("ascii").hex()
                s.sendall(self._pkt(f"qRcmd,{hex_cmd}"))
                # Drain: QEMU sends 0..N  "O<hex_text>" output packets then "OK"
                output = ""
                got_ok = False
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    resp = self._recv_pkt(s, timeout=1.0)
                    if not resp:
                        break
                    if resp == "OK":
                        got_ok = True
                        break
                    if resp.startswith("O"):
                        try:
                            output += bytes.fromhex(resp[1:]).decode("ascii", errors="replace")
                        except Exception:
                            pass
                    elif resp.startswith("E"):
                        output = resp
                        break
                s.sendall(self._pkt("c"))
                # Return "OK" when the command completed with no text output.
                # Return the text (which may contain "Error: ...") when QEMU
                # printed something - callers can check for error markers.
                return "OK" if got_ok and not output else output
        except Exception:
            return ""

    def savevm(self, name: str = "chess_ready") -> tuple[bool, str]:
        """Save a QEMU VM snapshot. Blocks until QEMU confirms (~10-30s).

        Returns ``(ok, message)``. ``ok=True`` means QEMU accepted the save
        (response was "OK" or non-Error text such as "Successfully saved...").
        ``message`` contains QEMU's stderr text on failure — most commonly
        ``"Error: State blocked by non-migratable device '...vhost-user-gpio'"``
        when the topology includes a device that does not support live
        migration.  Empty string on silent success.
        """
        resp = self.monitor_command(f"savevm {name}", timeout=self._SNAPSHOT_TIMEOUT)
        # monitor_command returns "OK" only when QEMU printed nothing.  A
        # successful savevm may print "Successfully saved..." then OK; a failed
        # one prints "Error: ..." then OK.  Use the presence of "Error:" as the
        # real failure signal rather than the absence of output.
        if resp == "OK":
            return True, ""
        if "Error:" in resp:
            return False, resp.strip()
        return True, resp.strip()

    def loadvm(self, name: str = "chess_ready") -> bool:
        """Restore a QEMU VM snapshot. Blocks until QEMU confirms (~5-15s)."""
        resp = self.monitor_command(f"loadvm {name}", timeout=self._SNAPSHOT_TIMEOUT)
        return resp == "OK"

    def system_reset(self) -> None:
        """Send a system_reset to QEMU - triggers a clean VM reboot."""
        self.monitor_command("system_reset", timeout=5.0)

    def writes_and_reads(self,
                         writes: list[tuple[int, int]],
                         reads:  list[tuple[int, int]]) -> list[bytes]:
        """
        Halt once, execute all writes then all reads, resume.

        Returns a list of bytes, one per read tuple (b"" on failure).
        All operations share the same GDB halt / MMU context.
        """
        results: list[bytes] = []
        try:
            with self._session() as (s, _):
                # Select CPU_A (thread 1) so memory ops target CHESS, not CPU_B/M4A.
                s.sendall(self._pkt("Hg1"))
                self._recv_pkt(s, timeout=1.0)
                for addr, value in writes:
                    le_hex = struct.pack("<I", value).hex()
                    s.sendall(self._pkt(f"M{addr:x},4:{le_hex}"))
                    self._recv_pkt(s, timeout=2.0)
                for addr, length in reads:
                    s.sendall(self._pkt(f"m{addr:x},{length:x}"))
                    resp = self._recv_pkt(s, timeout=max(2.0, length / 500))
                    data = (bytes.fromhex(resp)
                            if resp and all(c in "0123456789abcdefABCDEF" for c in resp)
                            else b"")
                    results.append(data)
                s.sendall(self._pkt("c"))
                # Wait for '+' ACK so QEMU processes 'c' before socket close.
                # Without this, QEMU 10.x may leave the CPU halted.
                s.settimeout(5.0)
                try:
                    s.recv(64)
                except (socket.timeout, OSError):
                    pass
        except Exception:
            while len(results) < len(reads):
                results.append(b"")
        return results

    def read_bulk(self, reads: list[tuple[int, int]]) -> list[bytes]:
        """
        Halt the CPU once, send one $m request per (addr, length) pair, then resume.

        All reads share a single GDB halt, so they are all taken from the same
        CPU/MMU context.  If the CPU halted in the wrong process (kernel or a
        different user process), every individual read will return b"" and the
        caller should retry.

        Parameters
        ----------
        reads : list of (guest_vaddr, byte_count) pairs

        Returns
        -------
        List of bytes objects, one per input pair (b"" on individual read failure).
        """
        results: list[bytes] = []
        try:
            with self._session() as (s, _):
                # Select CPU_A (thread 1) so reads target CHESS, not CPU_B/M4A.
                s.sendall(self._pkt("Hg1"))
                self._recv_pkt(s, timeout=1.0)
                for addr, length in reads:
                    s.sendall(self._pkt(f"m{addr:x},{length:x}"))
                    # Timeout scaled to data size; minimum 2 s
                    resp = self._recv_pkt(s, timeout=max(2.0, length / 500))
                    data = (bytes.fromhex(resp)
                            if resp and len(resp) % 2 == 0
                            and all(c in "0123456789abcdefABCDEF" for c in resp)
                            else b"")
                    results.append(data)
                s.sendall(self._pkt("c"))
                s.settimeout(5.0)
                try:
                    s.recv(64)
                except (socket.timeout, OSError):
                    pass
        except Exception:
            while len(results) < len(reads):
                results.append(b"")
        return results

    def redirect_pc(self, bad_pc: int) -> tuple[bool, int, int]:
        """
        Halt CPU, set PC (ARM register 15) to *bad_pc* via ``$G`` (write all
        registers), verify by read-back, then resume.

        Returns ``(write_ok, pc_before, pc_after)``.  ``write_ok`` is True only
        if the read-back PC matches *bad_pc*.

        Uses ``$G`` (write-all-registers) rather than ``$P`` (individual write)
        because some QEMU builds return OK for ``$P`` without applying it.
        """
        try:
            with self._session() as (s, _):
                # Read all registers ($g): ARM has >= 26 regs in GDB register file.
                # Core GPRs r0-r15 occupy the first 64 bytes (128 hex chars).
                s.sendall(self._pkt("g"))
                all_regs = self._recv_pkt(s, timeout=2.0)
                if not all_regs or len(all_regs) < 128:
                    s.sendall(self._pkt("c"))
                    return False, 0, 0

                pc_before = struct.unpack("<I", bytes.fromhex(all_regs[60*2:64*2]))[0]

                # Patch r15 (bytes 60-63 in the LE register dump)
                le_hex   = struct.pack("<I", bad_pc).hex()
                modified = all_regs[:60*2] + le_hex + all_regs[64*2:]

                # Write all registers ($G)
                s.sendall(self._pkt(f"G{modified}"))
                self._recv_pkt(s, timeout=2.0)

                # Read back to confirm
                s.sendall(self._pkt("g"))
                verify = self._recv_pkt(s, timeout=2.0)
                pc_after = 0
                if verify and len(verify) >= 128:
                    pc_after = struct.unpack("<I", bytes.fromhex(verify[120:128]))[0]

                write_ok = pc_after == bad_pc
                s.sendall(self._pkt("c"))
                return write_ok, pc_before, pc_after
        except Exception:
            return False, 0, 0

    def resume_cpu(self) -> None:
        """Resume a halted vCPU. No-op if CPU is already running.

        Connects, sends Ctrl-C to get current state, removes any pending SW BP
        at the current PC (to break stale-BP re-halt loops), then sends 'c'.
        """
        try:
            with self._session() as (s, stop_reply):
                # T05 reply format: "T05 pc:XXXXXXXX;..." (GDB RSP key-value pairs)
                # Parse PC and remove any stale SW BP to break re-halt loops.
                if stop_reply and "pc:" in stop_reply:
                    try:
                        pc_hex = stop_reply.split("pc:")[1].split(";")[0]
                        pc = int(pc_hex, 16) & ~1  # strip THUMB bit
                        for kind in (2, 4):
                            s.sendall(self._pkt(f"z0,{pc:x},{kind}"))
                            self._recv_pkt(s, timeout=1.0)
                    except Exception:
                        pass
                s.sendall(self._pkt("c"))
                s.settimeout(5.0)
                try:
                    s.recv(64)
                except (socket.timeout, OSError):
                    pass
        except Exception:
            pass

    def write_byte(self, addr: int, value: int, max_retries: int = 30) -> bool:
        """
        Halt QEMU, overwrite the byte at *addr* with *value*, read it back to
        verify, then resume.  Retries up to *max_retries* times if the read-back
        doesn't match — handles the common case where GDB halts the CPU in
        kernel context, the protocol-level write returns "OK", but the byte
        didn't actually land because the user-space page wasn't currently
        mapped.

        Returns True only if a read-back confirms the value landed; False if
        every retry attempt failed or hit an exception.
        """
        for attempt in range(max_retries):
            try:
                with self._session() as (s, _):
                    # Select CPU_A (thread 1) so the write targets CHESS, not
                    # CPU_B/M4A.  Matches writes_and_reads()'s context handling.
                    s.sendall(self._pkt("Hg1"))
                    self._recv_pkt(s, timeout=1.0)
                    # Write
                    s.sendall(self._pkt(f"M{addr:x},1:{value:02x}"))
                    self._recv_pkt(s, timeout=2.0)
                    # Verify by reading back the same byte
                    s.sendall(self._pkt(f"m{addr:x},1"))
                    resp = self._recv_pkt(s, timeout=2.0)
                    # Resume
                    s.sendall(self._pkt("c"))
                    s.settimeout(5.0)
                    try:
                        s.recv(64)
                    except (socket.timeout, OSError):
                        pass
                # Check the read-back: must be exactly the byte we wrote.
                if (resp and len(resp) >= 2
                        and all(c in "0123456789abcdefABCDEF" for c in resp[:2])):
                    actual = int(resp[:2], 16)
                    if actual == (value & 0xff):
                        if attempt > 0:
                            print(f"  write_byte: landed on attempt {attempt+1}",
                                  flush=True)
                        return True
            except Exception:
                pass
            if attempt < max_retries - 1:
                time.sleep(0.1)
        return False


# Low-level client

class PluginError(RuntimeError):
    pass


@dataclass
class InjectionSpec:
    addr: int              # guest virtual address (byte to flip)
    bit: int               # bit index 0-7 within the byte
    delay: int = 5_000_000 # instructions from *now* to inject
    symbol: str = ""       # demangled symbol name (optional)
    byte_offset: int = 0   # byte offset within the symbol
    field_name: str = ""   # DWARF field name within the symbol (optional)


@dataclass
class InjectionResult:
    spec: InjectionSpec
    trigger_insn: int      # absolute insn count when injection fired
    success: bool          # memory write succeeded
    original: int          # original byte value
    flipped: int           # byte value after flip
    elapsed_s: float       # wall time between schedule and confirm
    outcome: str        = "unknown"  # CRASH / DETECTED / MASKED
    evidence: str       = ""         # specific line that triggered the verdict
    last_events: list   = None       # last FPrime EVENT: lines seen (proof of life)
    recovery_path: str  = ""         # FS_RESTART | OS_REBOOT | "" (for CRASH only)
    recovery_time_s: float = None    # seconds from crash to CHESS ready
    # Layer-5 GOLDEN suspect evidence - populated by the per-injection critical-params
    # integrity check inside SEUCampaign.run_targets when a MASKED outcome has at least
    # one diverged param.  Format: "critical param diverged: <name> expected=<e> got=<a>".
    # Empty for non-MASKED outcomes and for MASKED results that passed the integrity check.
    suspect_reason: str = ""

    def __post_init__(self):
        if self.last_events is None:
            self.last_events = []

    def summary(self) -> str:
        sym_info = ""
        if self.spec.field_name:
            sym_info = f" ({self.spec.symbol} :: {self.spec.field_name})"
        elif self.spec.symbol:
            sym_info = f" ({self.spec.symbol} + {self.spec.byte_offset})"
        rec = f"  [{self.recovery_path} {self.recovery_time_s:.0f}s]" \
              if self.recovery_path and self.recovery_time_s is not None else ""
        return (
            f"addr=0x{self.spec.addr:08x}{sym_info} bit={self.spec.bit} "
            f"0x{self.original:02x}->0x{self.flipped:02x} "
            f"ok={self.success} insn={self.trigger_insn:,} "
            f"outcome={self.outcome}{rec}"
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

    # Context manager

    def __enter__(self):
        self.wait_for_socket()
        return self

    def __exit__(self, *_):
        pass

    # Helpers

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

    # API

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
                # Plugin signalled trigger perform GDB write if available.
                # When the plugin read failed (demand-paged BSS not faulted in),
                # r["flipped"] is stale/zero. Recompute from original and bit.
                if not r.get("success") and self._gdb is not None:
                    addr     = int(r["addr"])
                    bit      = int(r.get("bit", 0))
                    original = int(r.get("original", 0))
                    flipped  = original ^ (1 << bit)
                    ok = self._gdb.write_byte(addr, flipped)
                    r["original"] = original
                    r["flipped"]  = flipped
                    r["success"]  = ok
                    r["gdb_write"] = True
                return r
            time.sleep(poll_interval)
        return None


# Oracle: monitor PTY log for crash / detection signals

class PtyOracle:
    """
    Tail the QEMU serial PTY log and classify how the FS responded to a fault.

    Outcomes
    --------
    CRASH       guest/process died: kernel panic, SIGSEGV, FPrime Assert, or
                the FS stopped producing EVENT lines entirely (liveness timeout).
    DETECTED    FPrime's Svc::Health or any component logged a WARNING/ERROR/
                FATAL-severity EVR (generic, works for any component).
    MASKED      FS kept running and no anomaly was logged.

    Design rationale
    ----------------
    Patterns are component-agnostic.  Three independent signals are used:

    1. OS/process crash strings (kernel panic, segfault, abort, ...).
    2. FPrime-level crash: "Assert:" in the output (FW_ASSERT fires before exit).
    3. FPrime EVR severity: any EVR line that carries WARNING / ERROR / FATAL
       in its severity field covers Svc::Health ping warnings AND any future
       component that reports a fault through FPrime's event system.
    4. Liveness: if no "EVENT:" line appears for >LIVENESS_TIMEOUT_S seconds
       the FS is considered silent/crashed.
    """

    # 1. OS / process-level crash
    _OS_CRASH_RE = re.compile(
        r"Kernel panic|Oops:|segfault|SIGSEGV|illegal instruction"
        r"|Aborted|core dumped|BUG: Bad page",
        re.IGNORECASE,
    )

    # 2. FPrime process-level abort.
    # FW_ASSERT writes "Assert: <file>:<line>" to the serial console.
    # AssertFatalAdapter also logs the file path to the serial console, so we
    # match both its known format and the short "Assert:" prefix.
    _FPRIME_ASSERT_RE = re.compile(
        r'(^Assert:\s|AssertFatalAdapter)',
        re.MULTILINE,
    )

    # 3. FPrime EVR with WARNING / ERROR / FATAL severity.
    #    FPrime log format: "EVENT: (seq) (time) SEVERITY: (component) EVR_NAME"
    #    Only match inside actual EVENT: lines to avoid false positives from
    #    file paths (e.g. AssertFatalAdapter/AssertFatal**Adapter**.cpp contains
    #    the word "Fatal" but is a crash signal, not a health-monitoring event).
    _FPRIME_FAULT_RE = re.compile(
        r"EVENT:.*\b(WARNING_HI|WARNING_LO|FATAL"
        r"|HLTH_PING_WARN|HLTH_PING_LATE|HLTH_PING_WRONG_KEY)\b",
        re.IGNORECASE,
    )

    # Known background noise - events that fire in normal simulation operation
    # regardless of injections.  Matching these should NOT trigger DETECTED.
    # comQueue QueueOverflow: telemetry downlink queue fills when no real ground
    # station is connected.  This is an infrastructure condition, not a fault
    # response.
    _BACKGROUND_NOISE_RE = re.compile(
        r"comQueue.*(?:QueueOverflow|Overflow)|QueueOverflow.*comQueue",
        re.IGNORECASE,
    )

    # How long (seconds) without any EVENT: line before we declare the FS dead.
    # In TCG Docker mode F' emits EVRs only at startup and on faults - not
    # periodically in steady state.  Set the timeout larger than OBSERVATION_S
    # (120s) so the liveness check does not fire mid-observation; the real
    # liveness signal is the instruction-count oracle, not EVR frequency.
    LIVENESS_TIMEOUT_S: float = 300.0

    def __init__(self, pty_log_path: Union[Path, Tuple[str, int]],
                 seek_to_end: bool = False):
        """
        Parameters
        ----------
        pty_log_path :
            Either a ``Path`` to a local file/PTY to tail, or a ``(host, port)``
            tuple to read the serial console from a TCP socket.  The TCP form is
            used in Docker mode where the QEMU hvc0 console is exposed via
            ``chardev socket,port=<N>,...`` in the NEST topology.
        seek_to_end :
            When True and using a file source, seek to the current end of the
            file before reading.  Only new lines written after ``start()`` will
            be buffered.  Useful when the file already contains a large boot log
            and we only care about post-injection events.
        """
        if isinstance(pty_log_path, tuple):
            self._tcp_source: Tuple[str, int] | None = pty_log_path
            self.pty_log_path: Path | None = None
        else:
            self._tcp_source = None
            self.pty_log_path = pty_log_path
        self._seek_to_end = seek_to_end
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
        if self._tcp_source is not None:
            self._tail_tcp()
        else:
            self._tail_file()

    def _tail_file(self) -> None:
        while not self._stop.is_set():
            try:
                with self.pty_log_path.open("r", errors="replace") as f:  # type: ignore[union-attr]
                    if self._seek_to_end:
                        f.seek(0, 2)   # jump to end; only read new content
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
                time.sleep(0.5)
            except OSError:
                time.sleep(0.5)

    def _tail_tcp(self) -> None:
        """Tail serial console output from a QEMU TCP chardev socket."""
        host, port = self._tcp_source  # type: ignore[misc]
        buf = b""
        while not self._stop.is_set():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5.0)
                    s.connect((host, port))
                    s.settimeout(0.5)
                    buf = b""
                    while not self._stop.is_set():
                        try:
                            chunk = s.recv(4096)
                            if not chunk:
                                break
                            buf += chunk
                            while b"\n" in buf:
                                line_bytes, buf = buf.split(b"\n", 1)
                                stripped = line_bytes.decode("utf-8", errors="replace").rstrip("\r")
                                with self._lock:
                                    self._lines.append(stripped)
                                    if "EVENT:" in stripped:
                                        self._last_event_ts = time.monotonic()
                        except socket.timeout:
                            continue
            except (ConnectionRefusedError, OSError):
                time.sleep(1.0)

    def recent_lines(self, n: int = 100) -> list[str]:
        with self._lock:
            return list(self._lines[-n:])

    def drain(self) -> None:
        """Discard all accumulated log lines and reset the liveness clock.
        Call before scheduling each injection so classify() only sees events
        that occurred AFTER this point prevents stale events from a previous
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
                "last_events": [last <=5 FPrime EVENT lines seen],
            }

        ``evidence`` identifies the specific fault signal.
        ``last_events`` shows the most recent FS telemetry useful both as
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
                    if (self._FPRIME_FAULT_RE.search(line)
                            and not self._BACKGROUND_NOISE_RE.search(line)):
                        detected = True; evidence = f"[EVR] {line}"

            if detected:
                break

            # Liveness check: FS silent for too long -> crash/hang
            if not crashed and last_event_age > self.LIVENESS_TIMEOUT_S:
                crashed = True
                evidence = (f"[liveness] No EVENT: line for "
                            f"{last_event_age:.1f}s FS appears dead")
                break

            if crashed:
                break

            time.sleep(0.1)

        last_events = [l for l in self.recent_lines(60) if "EVENT:" in l][-5:]
        outcome = "CRASH" if crashed else ("DETECTED" if detected else "MASKED")
        return {"outcome": outcome, "evidence": evidence,
                "last_events": last_events}


# CHESS restart helper

def restart_chess_in_qemu(pty_log: Union[Optional[Path], Tuple[str, int]],
                          timeout: float = 120.0) -> bool:
    """
    Restart CHESS inside the running QEMU VM via the PTY device.

    In Docker mode (``pty_log`` is None or a TCP tuple), Phoenix handles restarts
    autonomously this function is a no-op and returns True immediately.

    Writes a shell command to /tmp/qemu-serial-pty that kills any residual
    CHESS process and relaunches it.  Then calls PtyOracle._wait_for_chess
    (reimplemented inline) to confirm the binary is live.

    Safe for BSS-target injections (anonymous memory is fresh per process).
    Text-segment injections corrupt the Linux page cache the restarted
    process loads the same corrupted page.
    """
    if pty_log is None or isinstance(pty_log, tuple):
        print("  Docker mode: Phoenix handles restart autonomously skipping PTY restart.",
              flush=True)
        return True

    CHESS_BINARY = "/CHESS/CHESS_Pathfinder0FS"
    if pty_log.suffix == ".out":
        pty_dev = pty_log.with_suffix(".in")
    else:
        pty_dev = Path("/tmp/qemu-serial-pty")

    # Record the size of the pty log before sending the restart command
    # so we don't match keywords from the previous run.
    start_offset = pty_log.stat().st_size if pty_log.exists() else 0

    try:
        with pty_dev.open("r+b", buffering=0) as pty:
            pty.write(b"\x03\n")    # Ctrl-C to kill any running foreground process
            time.sleep(0.5)
            pty.write(b"root\n")    # log in if we are at getty prompt
            time.sleep(0.5)
            pty.write(
                f"killall {CHESS_BINARY.split('/')[-1]} 2>/dev/null; "
                f"ulimit -c 0; {CHESS_BINARY} \n".encode()
            )
        print("  Sent PTY restart command.", flush=True)
    except OSError as e:
        print(f"  WARNING: Could not write to PTY ({e}); skipping restart.",
              flush=True)
        return False

    print(f"  Waiting for CHESS ready (watching {pty_log})...", flush=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            is_binary = pty_log.suffix != ".log"
            with pty_log.open("rb" if is_binary else "r",
                              **({} if is_binary else {"errors": "replace"})) as f:
                f.seek(start_offset)
                while time.monotonic() < deadline:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    decoded = line if isinstance(line, str) else line.decode(errors="replace")
                    if any(kw in decoded for kw in CHESS_READY_KEYWORDS):
                        print(f"  CHESS ready: {decoded.strip()}", flush=True)
                        return True
        except (FileNotFoundError, OSError):
            time.sleep(0.5)
    print("  WARNING: timed out waiting for CHESS restart.", flush=True)
    return False


# Higher-level campaign runner

@dataclass
class CampaignConfig:
    socket_path: Path
    elf_path: Path
    pty_log_path: Union[Path, Tuple[str, int]]  # file path or (host, port) TCP
    delay_insn: int          = 1_000_000   # instructions before each injection
    observation_window_s: float = 15.0     # seconds to wait for oracle verdict
    candidates_only: bool    = True        # only inject into FPrime variables
    filter_re: str | None    = None        # additional symbol name regex filter
    results_path: Path       = Path("/tmp/seu_results.jsonl")
    db_path: Path | None     = None
    # Docker/TCG mode: use instruction-count delta instead of serial EVENT: lines.
    # MASKED = vCPU still advancing; CRASH = vCPU halted.
    use_insn_count_liveness: bool = False
    # GDB host/port for fallback write when plugin direct_write=NO (stripped QEMU).
    gdb_host: str | None = None
    gdb_port: int        = 1234
    # Fast inter-injection recovery via QEMU VM snapshot.
    # Set snapshot_name to the name passed to savevm() before the campaign.
    # If set (and gdb_host is set), loadvm is used after every injection instead
    # of waiting for Phoenix to restart CHESS.
    snapshot_name: str | None = None
    # NEST WebSocket URL for M4B mux reset after loadvm (NEST components are not
    # restored by QEMU snapshots and must be reset explicitly).
    nest_url: str | None = None
    # Post-classification hook for pairwise invariant checks.
    #
    # Called after the PTY oracle classifies each injection.  Signature:
    #   hook(result: InjectionResult) -> str | None
    # Return value semantics:
    #   None          - keep the oracle's outcome as-is
    #   "<OUTCOME>"   - override result.outcome with this string
    #   "STOP"        - override outcome AND stop the campaign immediately.
    #                   The campaign raises _StopCampaign; callers should catch
    #                   it or let it propagate to abort CI with exit(1).
    #
    # Priority contract: the hook MUST NOT override "DETECTED" (FPrime already
    # observed the fault via its own health system).  It SHOULD override
    # "CRASH" and "MASKED" when a pairwise invariant violation is detected,
    # because INCONSISTENT / CORRUPTED is the root cause of such failures.
    classify_hook: Callable[["InjectionResult"], Optional[str]] = None  # type: ignore[assignment]
    # Override PtyOracle.LIVENESS_TIMEOUT_S (default 300s).  Set to a short
    # value (e.g. 5.0) when running against a no_phoenix topology so that
    # 5 s of console silence is sufficient to classify a crash.
    liveness_timeout_s: float | None = None
    # Layer-5 GOLDEN integrity check: list of safety-critical BSS words to
    # verify after every MASKED injection.  Build via
    # nest_client.seu.critical_params.build_health_critical_params() at boot,
    # then pass here.  When set, run_targets() reads all params via GDB after
    # each classify() (before the reset wipes state); any divergence is stashed
    # in result.suspect_reason and promotes the MASKED to "suspect" in the
    # summary report.  Unified across --ci and --ci-debug.
    critical_params: list = None  # list[CriticalParam] | None  (avoiding circular import)


class _StopCampaign(Exception):
    """Raised by classify_hook to cut a campaign early (e.g. INCONSISTENT found)."""


class SEUCampaign:
    """
    Orchestrates a sequence of SEU injections:

      1. Read ELF symbol table -> build list of injection targets
      2. For each target: schedule -> wait for firing -> classify outcome
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
        self._db = None
        self._run_id = None

    def start_db_run(self, topology: str = "sweep", notes: str = "") -> str:
        """Open the DB and create a run record. Returns the run_id.
        Enables per-result DB writes in both run_targets() and run_sweep()."""
        if not self.cfg.db_path:
            return ""
        from nest_client.seu.result_db import SEUResultDB
        self._db = SEUResultDB(self.cfg.db_path)
        self._run_id = self._db.start_run(
            elf_path=self.cfg.elf_path, topology=topology, notes=notes,
        )
        return self._run_id

    def setup_snapshot(self, name: str = "chess_ready") -> bool:
        """
        Save a QEMU VM snapshot for fast inter-injection recovery.

        Call this once after CHESS is ready (before run_targets).  Sets
        cfg.snapshot_name so run_targets will use loadvm after each injection
        instead of waiting for Phoenix to restart CHESS.

        Returns True on success, False if GDB is not configured or savevm fails.
        """
        if not self.cfg.gdb_host:
            print("  setup_snapshot: no GDB host configured - skipping", flush=True)
            return False
        gdb = GdbMemWriter(host=self.cfg.gdb_host, port=self.cfg.gdb_port)
        print(f"  Saving VM snapshot '{name}'...", flush=True)
        t0 = time.monotonic()
        ok, err = gdb.savevm(name)
        elapsed = time.monotonic() - t0
        if ok:
            self.cfg.snapshot_name = name
            print(f"  Snapshot '{name}' saved ({elapsed:.1f}s)", flush=True)
            return True
        # A non-migratable device in the QEMU topology (typically vhost-user-gpio)
        # is an expected limitation, not a bug downgrade to an informational
        # note.  Anything else is a real failure worth warning about.
        if "non-migratable device" in err:
            print(f"  Note: savevm unsupported by current QEMU topology "
                  f"({elapsed:.1f}s) — falling back to system_reset for "
                  f"crash recovery", flush=True)
        else:
            print(f"  WARNING: savevm '{name}' failed ({elapsed:.1f}s): {err} "
                  f"— falling back to system_reset for crash recovery", flush=True)
        return False

    # Core injection loop

    def _run_one(self,
                 client: FaultInjectorClient,
                 oracle: PtyOracle,
                 spec: InjectionSpec) -> InjectionResult:

        t0 = time.monotonic()
        trigger = client.inject_mem(addr=spec.addr, bit=spec.bit, delay=spec.delay)
        print(f"  Scheduled: addr=0x{spec.addr:08x} bit={spec.bit} "
              f"trigger_insn={trigger:,}")

        # Wait for the injection to fire.
        # Timeout must cover the delay interval: CHESS sleeps between rate-group
        # cycles so effective instruction rate can be ~1-2M insns/sec.
        # Assume at least 300K insns/sec (very conservative) plus a 10s buffer.
        fire_timeout = max(30.0, spec.delay / 300_000 + 10.0)
        plugin_resp = client.wait_for_result(
            timeout=fire_timeout,
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

        # GDB fallback write when plugin direct_write=NO (stripped QEMU binary).
        if not success and self.cfg.gdb_host and flipped != original:
            try:
                gdb = GdbMemWriter(host=self.cfg.gdb_host, port=self.cfg.gdb_port)
                success = gdb.write_byte(spec.addr, flipped)
            except Exception:
                pass

        # Drain background events that accumulated during the injection delay.
        # Any WARNING/ERROR that fired before the bit flip is pre-injection noise
        # (e.g. comQueue overflow from normal telemetry load) and must not be
        # counted as evidence of detection.
        oracle.drain()

        # Classify FPrime's response.
        # Always run the event oracle to catch DETECTED (WARNING/ERROR/FATAL
        # EVENT: lines).  Supplement with a fast instruction-count crash check:
        # if the vCPU stops advancing within 2 s of injection, that is a CRASH -
        # no need to wait out the full observation window.
        if self.cfg.use_insn_count_liveness:
            count_before = client.get_count()
            time.sleep(self.cfg.observation_window_s)
            count_after  = client.get_count()
            delta = count_after - count_before
            alive = delta > 1_000_000
            verdict = {
                "outcome":     "MASKED" if alive else "CRASH",
                "evidence":    f"insn delta={delta:,} ({'alive' if alive else 'halted'})",
                "last_events": [],
            }
        else:
            # Fast crash pre-check: 2 s instruction-count sample.
            # If the vCPU already halted we know the outcome immediately.
            _c0 = client.get_count()
            time.sleep(2.0)
            _c1 = client.get_count()
            if (_c1 - _c0) < 500_000:
                verdict = {
                    "outcome":  "CRASH",
                    "evidence": f"insn delta={_c1-_c0:,} over 2s - vCPU halted",
                    "last_events": [],
                }
            else:
                # vCPU alive - run the event oracle for the full half-window.
                # The 2 s crash check runs in parallel conceptually; do NOT
                # subtract it from the oracle budget so health-monitoring events
                # have enough time to fire (FPrime needs ~10 s).
                verdict = oracle.classify(self.cfg.observation_window_s * 0.5)

        result = InjectionResult(
            spec=spec,
            trigger_insn=trigger,
            success=success,
            original=original,
            flipped=flipped,
            elapsed_s=elapsed,
            outcome=verdict["outcome"],
            evidence=verdict.get("evidence", ""),
            last_events=verdict.get("last_events", []),
        )
        return result

    # Public API

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
        if self.cfg.liveness_timeout_s is not None:
            oracle.LIVENESS_TIMEOUT_S = self.cfg.liveness_timeout_s

        specs = list(specs)
        results = []
        # FPrime-level boot keywords (excludes Phoenix script echoes which fire
        # before FPrime initialises and would give a false "ready" signal).
        _FPRIME_BOOT_KW = [kw for kw in CHESS_READY_KEYWORDS
                           if kw != "CHESS_Pathfinder0FS"]
        # Phoenix restart / OS reboot signals for recovery_path classification.
        _FS_RESTART_RE  = re.compile(r"running\s+(stable|target|:)\s*/root/bin/")
        _OS_REBOOT_RE   = re.compile(r"Kernel panic|Oops:|BUG: Bad page",
                                     re.IGNORECASE)

        def _force_full_reset(result):
            # Used when per-byte revert can't guarantee independence (revert
            # failed, NO_INJECT, CRASH, DETECTED): fire system_reset, reset
            # the M4B mux, then wait for CHESS to come back up.
            _t_crash = time.monotonic()
            _rpath = ""
            if self.cfg.gdb_host:
                print("  Forcing system_reset for next-injection independence...",
                      flush=True)
                try:
                    _gdb_rst = GdbMemWriter(host=self.cfg.gdb_host,
                                            port=self.cfg.gdb_port)
                    _gdb_rst.system_reset()
                    _rpath = "OS_REBOOT"
                except Exception as _e:
                    print(f"  WARNING: system_reset failed ({_e})", flush=True)
                if self.cfg.nest_url:
                    try:
                        from nest_client.client import NestClient
                        with NestClient(url=self.cfg.nest_url) as _nc:
                            _nc.send_command("M4B",
                                             "switch_back_to_a7a", "{}")
                    except Exception as _e:
                        print(f"  WARNING: M4B reset failed ({_e})",
                              flush=True)
            _ready = ""
            _deadline = _t_crash + 120.0
            _boot_oracle = PtyOracle(self.cfg.pty_log_path, seek_to_end=True)
            _boot_oracle.start()
            try:
                while time.monotonic() < _deadline:
                    for line in _boot_oracle.recent_lines(500):
                        if not _rpath:
                            if _OS_REBOOT_RE.search(line):
                                _rpath = "OS_REBOOT"
                            elif _FS_RESTART_RE.search(line):
                                _rpath = "FS_RESTART"
                        if any(kw in line for kw in _FPRIME_BOOT_KW):
                            _ready = line.strip()
                            break
                    if _ready:
                        break
                    time.sleep(1.0)
            finally:
                _boot_oracle.stop()
            _rtime = time.monotonic() - _t_crash
            result.recovery_path   = _rpath or "UNKNOWN"
            result.recovery_time_s = round(_rtime, 1)
            if _ready:
                print(f"  CHESS ready ({result.recovery_path} "
                      f"{result.recovery_time_s:.0f}s): {_ready[:200]}",
                      flush=True)
            else:
                last = _boot_oracle.recent_lines(3)
                print(f"  WARNING: CHESS ready timeout "
                      f"({result.recovery_path}, "
                      f"{result.recovery_time_s:.0f}s). Last: {last}",
                      flush=True)

        try:
            with FaultInjectorClient(self.cfg.socket_path) as client:
              try:
                for i, spec in enumerate(specs):
                    oracle.drain()

                    # Formatted header line: show field name when available
                    _loc = (f"{spec.symbol} :: {spec.field_name}"
                            if spec.field_name else
                            (f"{spec.symbol} + {spec.byte_offset}"
                             if spec.symbol else f"0x{spec.addr:08x}"))
                    print(f"\n[{i+1}/{len(specs)}] {_loc}  "
                          f"addr=0x{spec.addr:08x}  bit={spec.bit}  "
                          f"delay={spec.delay:,} insns")

                    result = self._run_one(client, oracle, spec)

                    # Layer-5 GOLDEN integrity check
                    # Run BEFORE pairwise hook / reset / DB write because the
                    # upcoming reset (loadvm or system_reset) will wipe any
                    # corrupted state back to baseline.  MASKED-only: the
                    # other outcomes already have their own evidence path.
                    #
                    # When Layer-5 finds drift, we promote the outcome itself
                    # from MASKED to MASKED_CRITICAL.  Operationally that's a
                    # silent-corruption finding: the FS appears running but
                    # safety-critical state has been corrupted — same severity
                    # class as CRASH for downstream dashboards/alerting.
                    if result.outcome == "MASKED" and self.cfg.critical_params:
                        try:
                            from nest_client.seu.critical_params import check_critical_params
                            _gdb_l5 = GdbMemWriter(host=self.cfg.gdb_host,
                                                   port=self.cfg.gdb_port)
                            diverged = check_critical_params(self.cfg.critical_params, _gdb_l5)
                            if diverged:
                                name, exp, act = diverged[0]
                                extra = f" (+{len(diverged)-1} more)" if len(diverged) > 1 else ""
                                result.outcome = "MASKED_CRITICAL"
                                result.suspect_reason = (
                                    f"critical param diverged: {name} "
                                    f"expected={exp} got={act}{extra}"
                                )
                                print(f"  Layer-5: {len(diverged)} critical param(s) "
                                      f"diverged - first: {name} expected={exp} got={act} "
                                      "→ outcome promoted to MASKED_CRITICAL",
                                      flush=True)
                        except Exception as _e:
                            print(f"  WARNING: Layer-5 check failed ({_e})", flush=True)

                    # Pairwise invariant hook - runs after PTY oracle, before DB write.
                    # Priority: DETECTED and MASKED_CRITICAL are sacred findings:
                    #   - DETECTED        - FPrime itself observed the fault
                    #   - MASKED_CRITICAL - Layer-5 found safety-critical drift
                    # Both are real, evidenced findings; pairwise is a separate
                    # cross-subsystem invariant signal and shouldn't relabel them.
                    # For other outcomes (CRASH, MASKED, NO_INJECT), the hook can
                    # override with INCONSISTENT / CORRUPTED and optionally stop.
                    _sacred = ("DETECTED", "MASKED_CRITICAL")
                    if self.cfg.classify_hook and result.outcome not in _sacred:
                        hook_out = self.cfg.classify_hook(result)
                        if hook_out == "STOP":
                            results.append(result)
                            self._append_result(result)
                            print(f"  -> {result.summary()}", flush=True)
                            print(f"\n  *** CAMPAIGN STOPPED: pairwise invariant violated "
                                  f"on injection [{i+1}/{len(specs)}] ***", flush=True)
                            raise _StopCampaign(result.outcome)
                        elif hook_out is not None:
                            result.outcome = hook_out

                    results.append(result)
                    print(f"  -> {result.summary()}", flush=True)

                    # Show proof-of-life for MASKED (last EVENT: lines oracle saw)
                    if result.outcome == "MASKED" and result.last_events:
                        for ev in result.last_events[-2:]:
                            print(f"  oracle: {ev[:200]}", flush=True)

                    is_last = (i >= len(specs) - 1)

                    if not is_last and reset_between:
                        _t0 = time.monotonic()

                        if self.cfg.snapshot_name and self.cfg.gdb_host:
                            # Fast path: restore VM snapshot - works for all outcomes.
                            _gdb_snap = GdbMemWriter(host=self.cfg.gdb_host,
                                                     port=self.cfg.gdb_port)
                            _ok = _gdb_snap.loadvm(self.cfg.snapshot_name)
                            _rtime = round(time.monotonic() - _t0, 1)
                            result.recovery_path   = "SNAPSHOT"
                            result.recovery_time_s = _rtime
                            if _ok:
                                print(f"  Snapshot '{self.cfg.snapshot_name}' "
                                      f"restored ({_rtime:.1f}s)", flush=True)
                            else:
                                print(f"  WARNING: loadvm "
                                      f"'{self.cfg.snapshot_name}' failed",
                                      flush=True)
                            # M4B is a NEST WASM component - not restored by loadvm.
                            # Reset the mux to CPU_A so CHESS can reach sensors/UART.
                            if self.cfg.nest_url:
                                try:
                                    from nest_client.client import NestClient
                                    with NestClient(url=self.cfg.nest_url) as _nc:
                                        _nc.send_command("M4B",
                                                         "switch_back_to_a7a", "{}")
                                except Exception as _e:
                                    print(f"  WARNING: M4B reset failed ({_e})",
                                          flush=True)

                        elif (result.outcome in ("MASKED", "MASKED_CRITICAL")
                              and result.success):
                            # Restore the flipped byte via GDB so the next
                            # injection starts from a clean state.  Also applies
                            # to MASKED_CRITICAL Layer-5 found the corruption,
                            # but the next injection still needs the byte
                            # reverted, otherwise the persistent corruption
                            # cascades into every subsequent Layer-5 check and
                            # produces false "everything diverged" alarms.
                            _revert_ok = False
                            if self.cfg.gdb_host:
                                try:
                                    _gdb_r = GdbMemWriter(host=self.cfg.gdb_host,
                                                          port=self.cfg.gdb_port)
                                    _revert_ok = _gdb_r.write_byte(spec.addr, result.original)
                                    print(f"  Restored 0x{result.flipped:02x}->"
                                          f"0x{result.original:02x} at "
                                          f"0x{spec.addr:08x}  "
                                          f"({'ok' if _revert_ok else 'FAILED — escalating to system_reset'})",
                                          flush=True)
                                except Exception as _e:
                                    print(f"  WARNING: GDB restore failed ({_e})",
                                          flush=True)
                            if not _revert_ok:
                                # Per-byte revert can't guarantee independence
                                # (CPU halted, kernel context, GDB unreachable).
                                # Fall through to a full reboot so the next
                                # injection starts from a known-clean state.
                                _force_full_reset(result)

                        else:
                            # NO_INJECT / CRASH / DETECTED / MASKED-without-success:
                            # state is known-broken or unreliable. Force a full
                            # VM reboot so the next injection is truly independent.
                            _force_full_reset(result)

                        oracle.drain()

                    self._append_result(result)

              except _StopCampaign:
                pass  # hook cut the campaign; results collected so far are valid
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

        if self.cfg.db_path:
            from nest_client.seu.result_db import SEUResultDB
            self._db = SEUResultDB(self.cfg.db_path)
            self._run_id = self._db.start_run(
                elf_path=self.cfg.elf_path,
                topology="sweep",
                notes="automated sweep",
            )

        if max_targets:
            targets = targets[:max_targets]
            print(f"  (limited to first {max_targets})")

        specs = [
            InjectionSpec(addr=t["addr"], bit=t["bit"],
                          delay=self.cfg.delay_insn,
                          symbol=t.get("symbol", ""),
                          byte_offset=t.get("byte_offset", 0))
            for t in targets
        ]
        results = self.run_targets(specs)

        if on_result:
            for r in results:
                on_result(r)

        if self._db and self._run_id:
            self._db.print_run_summary(self._run_id)
            items = self._db.compare(self._run_id)
            self._db.print_review_queue(items)
            self._db.close()

        return results

    # Result persistence

    def _append_result(self, result: InjectionResult) -> None:
        record = {
            "addr":            f"0x{result.spec.addr:08x}",
            "symbol":          result.spec.symbol,
            "field_name":      result.spec.field_name,
            "byte_offset":     result.spec.byte_offset,
            "bit":             result.spec.bit,
            "trigger_insn":    result.trigger_insn,
            "success":         result.success,
            "original":        f"0x{result.original:02x}",
            "flipped":         f"0x{result.flipped:02x}",
            "elapsed_s":       round(result.elapsed_s, 3),
            "outcome":         result.outcome,
            "evidence":        result.evidence,
            "recovery_path":   result.recovery_path,
            "recovery_time_s": result.recovery_time_s,
        }
        with self.cfg.results_path.open("a") as f:
            f.write(json.dumps(record) + "\n")

        if self._db and self._run_id:
            self._db.record(
                run_id=self._run_id,
                addr=result.spec.addr,
                bit=result.spec.bit,
                original=result.original,
                flipped=result.flipped,
                write_ok=result.success,
                outcome=result.outcome,
                evidence=result.evidence,
                insn_count=result.trigger_insn,
                elf_path=self.cfg.elf_path,
                recovery_path=result.recovery_path,
                recovery_time_s=result.recovery_time_s,
            )

    def print_summary(self) -> None:
        """Unified SEU report - used by both --ci and --ci-debug.

        Outcome categories (top-level):
          CRASH           - vCPU halted / liveness timeout
          DETECTED        - FPrime WARN/FATAL event in observation window
          MASKED          - no event, no crash, Layer-5 clean (truly absorbed)
          MASKED_CRITICAL - no event, no crash, but Layer-5 found safety-critical
                            state drift (silent corruption — same severity class
                            as CRASH for operations / dashboards / alerting)
          NO_INJECT       - plugin never reported the trigger as fired

        Same format regardless of how injections were scheduled (random
        bit-flips in --ci vs user-chosen specs in --ci-debug).
        """
        from collections import Counter
        results = self._results
        total = len(results)

        counts = Counter(r.outcome for r in results)
        n_crash    = counts.get("CRASH",           0)
        n_detected = counts.get("DETECTED",        0)
        n_masked   = counts.get("MASKED",          0)
        n_critical = counts.get("MASKED_CRITICAL", 0)
        n_noinject = counts.get("NO_INJECT",       0)

        critical_results = [r for r in results if r.outcome == "MASKED_CRITICAL"]

        # Layer 4: pairwise violations (only meaningful when classify_hook is set)
        pairwise_violations: list = []
        hook = self.cfg.classify_hook
        if hook and hasattr(hook, "violations"):
            pairwise_violations = list(hook.violations)

        # Effective campaign size for percentages = total minus NO_INJECT
        # (failed injections aren't real data points).
        effective = total - n_noinject

        print("\n── SEU Campaign Report ──────────────────────────────")
        print(f"  Total injections     : {total}")
        if n_noinject:
            print(f"    NO_INJECT (failed) : {n_noinject}  "
                  f"(plugin never reported trigger fired — not real data)")
            print(f"  Effective injections : {effective}")
        print(f"   1. CRASH            : {n_crash}")
        print(f"   2. DETECTED         : {n_detected}")
        print(f"   3. MASKED           : {n_masked}    (Layer-5 verified - truly absorbed)")
        print(f"   4. MASKED_CRITICAL  : {n_critical}    (Layer-5 found silent corruption)")
        print(f"   5. PAIRWISE (state) : {len(pairwise_violations)}  "
              f"(EA x OBC invariant violation)")
        print("─────────────────────────────────────────────────────")

        if critical_results:
            print("\n  MASKED_CRITICAL — silent corruption (Layer-5 divergence):")
            for r in critical_results:
                sym = r.spec.symbol or f"0x{r.spec.addr:08x}"
                fld = f" :: {r.spec.field_name}" if r.spec.field_name else ""
                print(f"    0x{r.spec.addr:08x} bit={r.spec.bit}  {sym}{fld}")
                print(f"      → {r.suspect_reason}")

        if pairwise_violations:
            print("\n  PAIRWISE — EA x OBC state-machine violations:")
            for v in pairwise_violations:
                print(f"    {v['addr']} bit={v['bit']}  "
                      f"OBC={v['obc']} x EA={v['ea_post']}  → {v['verdict']}")

        if effective:
            print()
            for outcome in ("CRASH", "DETECTED", "MASKED", "MASKED_CRITICAL"):
                n = counts.get(outcome, 0)
                pct = 100 * n / effective
                print(f"  {outcome:<16} rate : {pct:5.1f}%  (of {effective} effective)")
        print(f"  Results file        : {self.cfg.results_path}")
        print("─────────────────────────────────────────────────────")


# CLI: quick manual injection

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
            print("Waiting for injection result...")
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
