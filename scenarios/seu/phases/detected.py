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

    # Find the PingTracker for "CdhCore_cmdDisp" in runtime BSS.
    #
    # PingTracker layout (stable across FPrime versions):
    #   +0:  warnCycles  (U64) = 3
    #   +8:  fatalCycles (U64) = 5
    #   +16: Fw::String vtable ptr  (4 bytes)
    #   +20: m_buf — the component name as a null-terminated ASCII string
    #   +280: cycleCount (U32)
    #
    # The running (optimised) binary's BSS layout may differ from the debug
    # ELF used for symbol resolution (dual-binary build).  We scan the full
    # BSS for the combined signature (warnCycles=3 + fatalCycles=5 + name)
    # rather than trusting the ELF symbol address.
    WARN_SIGN    = struct.pack("<Q", 3)   # warnCycles=3 U64
    FATAL_SIGN   = struct.pack("<Q", 5)  # fatalCycles=5 U64
    TARGET_NAME  = b"CdhCore_cmdDisp"
    PING_SIGN    = WARN_SIGN + FATAL_SIGN  # 16-byte prefix at PingTracker+0
    STEP         = 0x800  # 2 KB per GDB read

    def _find_pingtracker_in_region(base: int, size: int):
        """Scan a BSS region for a valid CdhCore_cmdDisp PingTracker.

        Returns (pingtracker_vaddr, cyclecount_vaddr) or None.
        A valid hit requires: PING_SIGN at offset 0 AND TARGET_NAME at offset +20.
        """
        buf = b""
        off = 0
        while off < size:
            chunk_size = min(STEP, size - off)
            chunk = b"".join(_gdb.read_bulk([(base + off, chunk_size)]))
            if chunk:
                buf += chunk
            else:
                buf += b"\x00" * chunk_size   # fill unmapped gaps with zeros
            off += chunk_size

        # Search for PING_SIGN; verify TARGET_NAME at +20
        search_start = 0
        while True:
            i = buf.find(PING_SIGN, search_start)
            if i < 0:
                return None
            # Check TARGET_NAME 20 bytes after PING_SIGN start
            name_off = i + 20
            if name_off + len(TARGET_NAME) <= len(buf):
                if buf[name_off:name_off + len(TARGET_NAME)] == TARGET_NAME:
                    pt_vaddr = base + i
                    return pt_vaddr, pt_vaddr + 280
            search_start = i + 1

    print(f"  Searching BSS for PingTracker(warnCycles=3, name='CdhCore_cmdDisp')…",
          flush=True)

    # Try ELF health BSS first (fast path when binaries match).
    result = _find_pingtracker_in_region(health_sym.address, health_sym.size)

    if result is None:
        # Try pingEntries (newer FPrime topology layout).
        ping_sym = next((s for s in symbols
                         if "pingEntries" in s.demangled
                         and "CdhCore" in s.demangled
                         and s.section == ".bss"), None)
        if ping_sym:
            print(f"  Not in health BSS — trying pingEntries "
                  f"@ 0x{ping_sym.address:08x}…", flush=True)
            result = _find_pingtracker_in_region(ping_sym.address, ping_sym.size)

    if result is None:
        # Wide BSS scan: covers dual-binary BSS layout divergence.
        bss_syms  = sorted((s for s in symbols if s.section == ".bss"),
                            key=lambda s: s.address)
        bss_base  = bss_syms[0].address if bss_syms else 0xbf000
        bss_limit = min(bss_base + 0x200000,
                        max((s.address + s.size for s in bss_syms),
                            default=bss_base + 0x100000))
        print(f"  Wide BSS scan 0x{bss_base:08x}…0x{bss_limit:08x} "
              f"({(bss_limit-bss_base)//1024} KB)…", flush=True)
        result = _find_pingtracker_in_region(bss_base, bss_limit - bss_base)

    if result is None:
        print("ERROR: could not locate CdhCore_cmdDisp PingTracker in BSS")
        return

    found_base, cycleCount_addr = result
    string_vaddr = found_base + 20
    key_addr     = found_base + 284
    enabled_addr = found_base + 288
    bss_offset   = found_base - health_sym.address   # offset from ELF health sym

    print(f"  Found 'CdhCore_cmdDisp' @ 0x{string_vaddr:08x}", flush=True)
    print(f"  PingTracker base @ 0x{found_base:08x}  "
          f"(offset {bss_offset:+d} from ELF health symbol)")
    print(f"  cycleCount @ 0x{cycleCount_addr:08x}  enabled @ 0x{enabled_addr:08x}")

    # The scan validated warnCycles=3 + fatalCycles=5 as part of its signature,
    # so no further init check is needed.
    def _u32(b: bytes):
        return struct.unpack_from("<I", b)[0] if len(b) >= 4 else None

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
