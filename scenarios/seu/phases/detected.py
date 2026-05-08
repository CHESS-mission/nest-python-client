"""Phase: DETECTED — cycleCount injection into CdhCore::health PingTracker."""

from __future__ import annotations

import json
import struct
import time

from nest_client.seu.injector import FaultInjectorClient, GdbMemWriter, PtyOracle
from nest_client.seu import elf_analyzer

from ..config import (
    ELF_PATH, SOCK_PATH, RESULTS,
    _docker_mode, PTY_LOG, GDB_HOST, CONSOLE_LOG, CONSOLE_HOST, CONSOLE_PORT,
)
from ..helpers import _insn_delta, print_banner


def run_detected_phase(args, pre_oracle=None) -> None:
    """
    Demonstrate DETECTED: write cycleCount=warnCycles to a PingTracker, wait
    for HealthImpl::Run_handler to fire, confirm via cycleCount read-back.

    Oracle selection (priority order):
      1. pre_oracle (TCP, pre-connected) — simple topology, no Phoenix.
      2. CONSOLE_LOG (file chardev) — redundancy topology.
      3. PTY_LOG — non-Docker local PTY.
    """
    WARN_CYCLES     = 3
    INJECT_CC       = WARN_CYCLES
    SETTLE_S        = 3.0
    HEALTH_WAIT_S   = 10.0

    print_banner("SEU DETECTED Demo  HLTH_PING_WARN via health cycleCount injection")

    _gdb = GdbMemWriter(GDB_HOST, 1234)

    # Clear any stale GDB state from a previous run.
    _gdb.resume_cpu()
    time.sleep(0.5)

    # Wait for CHESS to reach steady state (boot rate is 100–170 M insns/s).
    if _docker_mode:
        _boot_rate = _insn_delta(2.0) / 2.0
        if _boot_rate > 10_000_000:
            print(f"  System in boot phase ({_boot_rate/1e6:.0f}M insns/s) — "
                  f"waiting up to 60s for steady state…", flush=True)
            for _ in range(12):
                time.sleep(5.0)
                _ss_rate = _insn_delta(2.0) / 2.0
                if _ss_rate <= 10_000_000:
                    print(f"  Steady state reached ({_ss_rate/1e6:.1f}M insns/s) ✓", flush=True)
                    break

    # Select oracle source.
    if pre_oracle is not None:
        oracle        = pre_oracle
        console_label = f"{CONSOLE_HOST}:{CONSOLE_PORT} (TCP pre-connected)"
        _own_oracle   = False
    elif CONSOLE_LOG is not None:
        oracle        = PtyOracle(CONSOLE_LOG)
        oracle.start()
        console_label = str(CONSOLE_LOG)
        _own_oracle   = True
    else:
        oracle        = PtyOracle(PTY_LOG)
        oracle.start()
        console_label = str(PTY_LOG)
        _own_oracle   = True

    print(f"Console oracle: {console_label}")
    boot_deadline = time.monotonic() + 60.0
    event_lines: list[str] = []
    while time.monotonic() < boot_deadline and not event_lines:
        time.sleep(2.0)
        snap        = oracle.recent_lines(200)
        event_lines = [l for l in snap if "EVENT:" in l]
    if event_lines:
        print(f"  F' active  {len(event_lines)} EVENT: lines seen ✓")
        print(f"  Last: {event_lines[-1][:100]}")
    else:
        print(f"  No EVENT: lines — proceeding.")

    # Resolve addresses from ELF and scan BSS for PingTracker.
    print(f"\nResolving target from ELF: {ELF_PATH.name}…")
    if not ELF_PATH.exists():
        print(f"ERROR: ELF not found at {ELF_PATH}")
        return

    symbols = elf_analyzer.analyze(ELF_PATH)
    health_sym = next((s for s in symbols
                       if "health" in s.demangled.lower()
                       and "CdhCore" in s.demangled
                       and s.section == ".bss"
                       and "pingEntries" not in s.demangled), None)
    if health_sym is None:
        print("ERROR: CdhCore::health not found in ELF")
        return
    print(f"  CdhCore::health  @ 0x{health_sym.address:08x}  size={health_sym.size}")

    write_msg_sym = next((s for s in symbols
                          if "PosixConsole" in s.demangled
                          and "writeMessage" in s.demangled
                          and s.section == ".text"), None)
    WRITE_MSG_ADDR = (write_msg_sym.address & ~1) if write_msg_sym else 0x00016ce8
    print(f"  PosixConsole::writeMessage @ 0x{WRITE_MSG_ADDR:08x}")

    # Scan health BSS for "CdhCore_cmdDisp" to locate the PingTracker.
    TARGET_STR   = b"CdhCore_cmdDisp"
    health_start = health_sym.address
    health_size  = health_sym.size
    print(f"  Scanning health BSS for 'CdhCore_cmdDisp'…", flush=True)

    step      = 0x200
    read_specs = [(health_start + off, min(step, health_size - off))
                  for off in range(0, health_size, step)]
    rb_all    = _gdb.read_bulk(read_specs)
    data      = b"".join(rb_all)
    idx       = data.find(TARGET_STR)
    if idx < 0:
        print("ERROR: could not locate CdhCore_cmdDisp PingTracker in health BSS")
        return

    string_vaddr    = health_start + idx
    found_base      = string_vaddr - 20    # m_buf is at PingTracker+20
    cycleCount_addr = found_base + 280
    key_addr        = found_base + 284
    enabled_addr    = found_base + 288
    bss_offset      = found_base - health_start
    print(f"  Found 'CdhCore_cmdDisp' @ 0x{string_vaddr:08x}", flush=True)
    print(f"  PingTracker base @ 0x{found_base:08x}  (BSS+{bss_offset})")
    print(f"  cycleCount @ 0x{cycleCount_addr:08x}  enabled @ 0x{enabled_addr:08x}")

    # Confirm warnCycles=3 (CHESS fully initialised).
    def _u32(b: bytes):
        return struct.unpack_from("<I", b)[0] if len(b) >= 4 else None

    for _init_attempt in range(6):
        rb_wc = _gdb.read_bulk([(found_base, 8)])
        wc_val = struct.unpack_from("<Q", rb_wc[0])[0] if rb_wc and len(rb_wc[0]) >= 8 else 0
        if wc_val == 3:
            break
        print(f"  PingTracker warnCycles={wc_val} (expected 3) — "
              f"waiting 5s for CHESS init…", flush=True)
        time.sleep(5.0)
        rb_all2 = _gdb.read_bulk(read_specs)
        data2   = b"".join(rb_all2)
        idx2    = data2.find(TARGET_STR)
        if idx2 >= 0:
            found_base      = health_start + idx2 - 20
            cycleCount_addr = found_base + 280
    else:
        print("WARNING: PingTracker warnCycles never became 3 — proceeding anyway", flush=True)

    # Inject cycleCount and wait for HealthImpl to fire.
    print(f"\nWaiting {SETTLE_S:.0f}s for comQueue overflow to settle…", flush=True)
    time.sleep(SETTLE_S)

    print(f"Injecting cycleCount={INJECT_CC} via direct GDB write…")
    oracle.drain()

    _gdb.writes_and_reads(writes=[(cycleCount_addr, INJECT_CC)], reads=[])
    print(f"  Wrote cycleCount={INJECT_CC} to 0x{cycleCount_addr:08x}", flush=True)

    rb_verify = _gdb.read_bulk([(cycleCount_addr, 4)])
    cc_verify = _u32(rb_verify[0] if rb_verify else b"")
    print(f"  cycleCount verified: {cc_verify}  (should be {INJECT_CC})", flush=True)
    if cc_verify != INJECT_CC:
        print(f"  WARNING: write may have failed (got {cc_verify}, expected {INJECT_CC})", flush=True)

    time.sleep(1.0)
    _fi_delta = _insn_delta(2.0)
    if _fi_delta < 10_000:
        print("  CPU halted after write — sending resume…", flush=True)
        _gdb.resume_cpu()
        time.sleep(1.0)
    else:
        print(f"  CPU running  (delta={_fi_delta:,} insns/2s) ✓", flush=True)

    print(f"  Waiting {HEALTH_WAIT_S:.0f}s for health Run_handler to fire…", flush=True)
    time.sleep(HEALTH_WAIT_S)

    rb_cc   = _gdb.read_bulk([(cycleCount_addr, 4)])
    cc_post = _u32(rb_cc[0] if rb_cc else b"")
    print(f"  cycleCount after wait: {cc_post}  "
          f"(injected {INJECT_CC}; expect ≠{INJECT_CC} if WARN fired)", flush=True)

    warn_fired   = False
    gdb_evidence = ""
    if cc_verify == INJECT_CC and cc_post != INJECT_CC:
        warn_fired   = True
        gdb_evidence = (f"[GDB cycleCount] write verified ({INJECT_CC}), "
                        f"cycleCount advanced to {cc_post} -> HLTH_PING_WARN fired")
        print(f"  ✓ WARN confirmed: cycleCount {INJECT_CC}->{cc_post}", flush=True)
    elif cc_verify != INJECT_CC:
        print(f"  write unverified (got {cc_verify}) — cannot confirm WARN", flush=True)
    else:
        print(f"  cycleCount still {cc_post} — WARN may not have fired", flush=True)

    # Reset cycleCount to prevent HLTH_PING_LATE FATAL on next Run_handler.
    _gdb.writes_and_reads(writes=[(cycleCount_addr, 0)], reads=[])
    print(f"  cycleCount reset to 0", flush=True)

    oracle_v = oracle.classify(observation_window_s=1.0)

    if warn_fired:
        outcome  = "DETECTED"
        evidence = gdb_evidence
    else:
        _delta = _insn_delta(2.0)
        if _delta > 500_000:
            outcome  = "MASKED"
            evidence = (f"HLTH_PING_WARN not seen; cycleCount unchanged "
                        f"(insn delta={_delta:,}, F' alive)")
        else:
            outcome  = "CRASH"
            evidence = f"vCPU halted after injection (insn delta={_delta:,})"

    colour = {"DETECTED": "\033[92m", "MASKED": "\033[93m",
              "CRASH": "\033[91m"}.get(outcome, "")
    print(f"\nVerdict: {colour}{outcome}\033[0m")
    print(f"  Evidence: {evidence}")

    if _own_oracle:
        oracle.stop()

    with RESULTS.open("a") as rf:
        rf.write(json.dumps({
            "target":            f"CdhCore::health PingTracker[0].cycleCount @ 0x{cycleCount_addr:08x}",
            "inject_cycleCount": INJECT_CC,
            "warn_cycles":       WARN_CYCLES,
            "outcome":           outcome,
            "evidence":          evidence,
        }) + "\n")
    print(f"\nResult appended to {RESULTS}")
