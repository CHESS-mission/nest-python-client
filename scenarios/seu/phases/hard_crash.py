"""Phase: HARD_CRASH — FPrime FATAL via cycleCount injection -> CRASH_RECOVERED."""

from __future__ import annotations

import json
import struct
import time

from nest_client.seu.injector import GdbMemWriter, PtyOracle
from nest_client.seu import elf_analyzer
from nest_client.client import NestClient

from ..config import (
    ELF_PATH, RESULTS, NEST_URL,
    _docker_mode, PTY_LOG, GDB_HOST,
)
from ..helpers import _insn_delta, print_banner


def _find_cmddisp_pingtracker(gdb: GdbMemWriter, symbols) -> int | None:
    """Scan BSS for the CdhCore_cmdDisp PingTracker; return its base address.

    Identical signature scan used by --detected: locates the PingTracker via
    its content (warnCycles=3 + fatalCycles=5 + name="CdhCore_cmdDisp") so the
    test is immune to debug/running BSS layout divergence.
    """
    WARN_SIGN   = struct.pack("<Q", 3)
    FATAL_SIGN  = struct.pack("<Q", 5)
    PING_SIGN   = WARN_SIGN + FATAL_SIGN
    TARGET_NAME = b"CdhCore_cmdDisp"
    STEP        = 0x800

    def scan(base: int, size: int) -> int | None:
        buf = b""
        off = 0
        while off < size:
            cs = min(STEP, size - off)
            ch = b"".join(gdb.read_bulk([(base + off, cs)]))
            buf += ch if ch else (b"\x00" * cs)
            off += cs
        search = 0
        while True:
            i = buf.find(PING_SIGN, search)
            if i < 0:
                return None
            no = i + 20
            if no + len(TARGET_NAME) <= len(buf) and buf[no:no + len(TARGET_NAME)] == TARGET_NAME:
                return base + i
            search = i + 1

    # Pass 1: ELF health symbol
    health_sym = next((s for s in symbols
                       if "health" in s.demangled.lower()
                       and "CdhCore" in s.demangled
                       and s.section == ".bss"
                       and "pingEntries" not in s.demangled), None)
    if health_sym:
        r = scan(health_sym.address, health_sym.size)
        if r is not None:
            return r

    # Pass 2: pingEntries
    ping_sym = next((s for s in symbols
                     if "pingEntries" in s.demangled
                     and "CdhCore" in s.demangled
                     and s.section == ".bss"), None)
    if ping_sym:
        r = scan(ping_sym.address, ping_sym.size)
        if r is not None:
            return r

    # Pass 3: wide BSS scan
    bss_syms  = sorted((s for s in symbols if s.section == ".bss"),
                       key=lambda s: s.address)
    bss_base  = bss_syms[0].address if bss_syms else 0xbf000
    bss_limit = min(bss_base + 0x200000,
                    max((s.address + s.size for s in bss_syms),
                        default=bss_base + 0x100000))
    return scan(bss_base, bss_limit - bss_base)


def run_hard_crash_phase(_args) -> None:
    """
    Write cycleCount > fatalCycles into the CdhCore_cmdDisp PingTracker.

    On the next HealthImpl::Run_handler tick (≤1 s real-time), FPrime detects
    the fatal threshold breach, logs HLTH_PING_LATE FATAL, and triggers the
    assertion handler -> SIGABRT -> Phoenix restarts CHESS -> CRASH_RECOVERED.

    This replaces the previous vtable-bit-flip approach which broke after the
    dual-binary CHESS FS build (BSS layout divergence between debug ELF and
    running binary).  Locating the PingTracker via runtime signature scan is
    binary-version-stable.
    """
    FATAL_CYCLE_VALUE = 100         # >> fatalCycles=5, guarantees FATAL fire
    CRASH_WINDOW      = 8.0
    RECOVERY_WINDOW   = 20.0
    SETTLE_S          = 5.0

    if not ELF_PATH.exists():
        print(f"ERROR: ELF not found at {ELF_PATH}")
        return

    symbols = elf_analyzer.analyze(ELF_PATH)

    print_banner("SEU Hard-Crash Demo  FPrime FATAL via cycleCount injection")
    print(f"  Target : CdhCore_cmdDisp PingTracker.cycleCount")
    print(f"  Write  : cycleCount = {FATAL_CYCLE_VALUE}  (fatalCycles=5)")
    print(f"  Method : GDB write — found via BSS signature scan")
    print(f"  Oracle : crash_window={CRASH_WINDOW}s  recovery_window={RECOVERY_WINDOW}s\n")

    oracle = PtyOracle(PTY_LOG)
    oracle.start()

    try:
        gdb = GdbMemWriter(host=GDB_HOST, port=1234)

        print(f"Waiting {SETTLE_S:.0f}s for CHESS to settle…")
        time.sleep(SETTLE_S)
        oracle.drain()

        if _docker_mode:
            print("  Scanning BSS for CdhCore_cmdDisp PingTracker…", flush=True)
            pt_base = _find_cmddisp_pingtracker(gdb, symbols)
            if pt_base is None:
                print("ERROR: could not locate CdhCore_cmdDisp PingTracker")
                return
            HARD_CRASH_ADDR = pt_base + 280   # cycleCount offset
            print(f"  PingTracker @ 0x{pt_base:08x}  cycleCount @ 0x{HARD_CRASH_ADDR:08x}")

            rate_base = _insn_delta(CRASH_WINDOW) / CRASH_WINDOW
            print(f"  Baseline insn rate (pre-injection): {rate_base:,.0f}/s")

            print(f"Injecting cycleCount={FATAL_CYCLE_VALUE} at 0x{HARD_CRASH_ADDR:08x}…")
            # Retry write+verify until the write lands in user context.
            verify_val = 0
            for attempt in range(30):
                gdb.writes_and_reads(writes=[(HARD_CRASH_ADDR, FATAL_CYCLE_VALUE)], reads=[])
                verify = gdb.read_bulk([(HARD_CRASH_ADDR, 4)])
                if verify and len(verify[0]) >= 4:
                    verify_val = struct.unpack_from('<I', verify[0])[0]
                    if verify_val == FATAL_CYCLE_VALUE:
                        print(f"  Write landed (attempt {attempt+1}): cycleCount={verify_val} ✓",
                              flush=True)
                        break
                time.sleep(0.1)
            else:
                print(f"  WARNING: write never verified after 30 attempts "
                      f"(last verify={verify_val}) — proceeding", flush=True)
            rate_crash = _insn_delta(CRASH_WINDOW) / CRASH_WINDOW
            crashed_insn = (rate_crash < rate_base * 0.70 or rate_crash > rate_base * 2.0)
            crash_evidence = (f"insn rate {rate_crash:,.0f}/s over {CRASH_WINDOW}s "
                              f"(baseline {rate_base:,.0f}/s; "
                              f"{'↓ crash' if crashed_insn else '-> alive'})")
            print(f"\n  insn rate after injection: {rate_crash:,.0f}/s  "
                  f"(baseline {rate_base:,.0f}/s, threshold 50%={rate_base*0.5:,.0f})", flush=True)
            if not crashed_insn:
                print(f"\nOutcome: MASKED  (insn rate unchanged, no crash detected)")
                print(f"  {crash_evidence}")
                return
            print(f"\n\033[91mCRASH\033[0m  evidence: {crash_evidence}")
        else:
            print("Non-Docker mode not supported for cycleCount injection (no GDB host).")
            return

        # Phase 2: watch for autonomous recovery.
        print(f"Observing {RECOVERY_WINDOW:.0f}s for autonomous recovery…")
        oracle.drain()
        if _docker_mode:
            soft_reboot_seen = False
            try:
                with NestClient(url=NEST_URL) as _nc:
                    try:
                        _nc.wait_for_event(component="M4A", event="SOFT_REBOOT_A7A",
                                           timeout=RECOVERY_WINDOW)
                        soft_reboot_seen = True
                    except Exception:
                        pass
            except Exception:
                pass

            cpu_alive = _insn_delta(3.0) > 100_000

            if not cpu_alive:
                recovered, recovery_path = False, "HARD_CRASH"
                rec_evidence = "vCPU halted no autonomous recovery"
            elif soft_reboot_seen:
                recovered, recovery_path = True, "OS_REBOOT"
                rec_evidence = "M4A fired SOFT_REBOOT_A7A -> full Linux reboot + Phoenix restart"
            else:
                recovered, recovery_path = True, "FS_RESTART"
                rec_evidence = "No M4A reboot Phoenix restarted F' without OS reboot"

            final = "CRASH_RECOVERED" if recovered else "HARD_CRASH"
        else:
            rec_v = oracle.classify(observation_window_s=RECOVERY_WINDOW)
            recovered    = bool(rec_v.get("last_events"))
            rec_evidence = rec_v.get("evidence", "")
            recovery_path = "FS_RESTART" if recovered else "HARD_CRASH"
            final = "CRASH_RECOVERED" if recovered else "HARD_CRASH"

        colour = "\033[92m" if recovered else "\033[91m"
        print(f"\nFinal verdict: {colour}{final}\033[0m")
        print(f"  Recovery path : {recovery_path}")
        print(f"  Evidence      : {rec_evidence}")

        with RESULTS.open("a") as rf:
            rf.write(json.dumps({
                "addr":           f"0x{HARD_CRASH_ADDR:08x}",
                "symbol":         "CdhCore_cmdDisp PingTracker.cycleCount",
                "injected_value": FATAL_CYCLE_VALUE,
                "outcome":        final,
                "recovery_path":  recovery_path,
                "evidence":       crash_evidence,
                "rec_evidence":   rec_evidence,
            }) + "\n")
        print(f"\nResult appended to {RESULTS}")

    finally:
        oracle.stop()
