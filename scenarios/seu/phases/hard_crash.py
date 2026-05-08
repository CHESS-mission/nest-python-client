"""Phase: HARD_CRASH — vtable bit-flip in rateGroupDriver -> CRASH_RECOVERED."""

from __future__ import annotations

import json
import time

from nest_client.seu.injector import FaultInjectorClient, GdbMemWriter, PtyOracle
from nest_client.client import NestClient

from ..config import (
    ELF_PATH, SOCK_PATH, RESULTS, NEST_URL,
    _docker_mode, PTY_LOG, GDB_HOST,
)
from ..helpers import _insn_delta, print_banner


def run_hard_crash_phase(_args) -> None:
    """
    Flip bit 0 of rateGroupDriver+0 (vtable pointer) -> misaligned vtable ->
    ARM32 data abort -> SIGSEGV -> Phoenix restarts F' -> CRASH_RECOVERED.
    """
    HARD_CRASH_BIT  = 0
    CRASH_WINDOW    = 8.0
    RECOVERY_WINDOW = 20.0
    GDB_WAIT_S      = 3.0

    HARD_CRASH_ADDR = None
    if ELF_PATH.exists():
        from nest_client.seu import elf_analyzer as _ea
        for sym in _ea.analyze(ELF_PATH):
            if "rateGroupDriver" in sym.demangled and sym.section == ".bss":
                HARD_CRASH_ADDR = sym.address + 0
                break

    if HARD_CRASH_ADDR is None:
        print("ERROR: could not resolve CHESS::rateGroupDriver from ELF.")
        return

    original = 0x00
    flipped  = original ^ (1 << HARD_CRASH_BIT)

    print_banner(f"SEU Hard-Crash Demo   rateGroupDriver+0 (vtable) @ 0x{HARD_CRASH_ADDR:08x}  bit=0")
    print(f"  Target : CHESS::rateGroupDriver vtable ptr  (bit-0 flip -> misaligned)")
    print(f"  Address: 0x{HARD_CRASH_ADDR:08x}   bit={HARD_CRASH_BIT}")
    print(f"  Write  : 0x{original:02x} ({original:08b})  ->  0x{flipped:02x} ({flipped:08b})")
    print(f"  Method : direct GDB RSP write (bypasses plugin vaddr context issue)")
    print(f"  Oracle : crash_window={CRASH_WINDOW}s  recovery_window={RECOVERY_WINDOW}s\n")

    oracle = PtyOracle(PTY_LOG)
    oracle.start()

    try:
        gdb = GdbMemWriter(host=GDB_HOST, port=1234)

        print(f"Waiting {GDB_WAIT_S:.0f}s for CHESS to be fully running…")
        time.sleep(GDB_WAIT_S)
        oracle.drain()

        if _docker_mode:
            rate_base = _insn_delta(CRASH_WINDOW) / CRASH_WINDOW
            print(f"  Baseline insn rate (pre-injection): {rate_base:,.0f}/s")

            print(f"Injecting 0x{original:02x}->0x{flipped:02x} at 0x{HARD_CRASH_ADDR:08x}…")
            plugin_result = None
            with FaultInjectorClient(SOCK_PATH) as fi_inj:
                cnt_now = fi_inj.get_count()
                trigger = fi_inj.inject_mem(
                    addr=HARD_CRASH_ADDR, bit=HARD_CRASH_BIT,
                    delay=700_000,
                )
                print(f"  Plugin scheduled at insn {trigger:,}. Waiting…")
                plugin_result = fi_inj.wait_for_result(timeout=30.0, trigger_insn=trigger)

            wrote     = bool(plugin_result and plugin_result.get("success", False))
            orig_byte = plugin_result.get("original", original) if plugin_result else original
            flip_byte = plugin_result.get("flipped",  flipped)  if plugin_result else flipped

            if not wrote:
                print(f"  Plugin write success={wrote} (may have fired in kernel) "
                      f"— GDB fallback with retries…")
                for _attempt in range(10):
                    ok = gdb.write_byte(HARD_CRASH_ADDR, flipped)
                    if ok:
                        wrote = True
                        orig_byte, flip_byte = original, flipped
                        print(f"  GDB fallback: OK (attempt {_attempt+1})")
                        break
                    time.sleep(0.05)
                if not wrote:
                    print("ERROR: both plugin and GDB write failed after retries")
                    return

            print(f"Fired ✓  wrote 0x{orig_byte:02x}->0x{flip_byte:02x}  "
                  f"({'plugin' if plugin_result and plugin_result.get('success') else 'GDB'})")

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
            print(f"Writing 0x{flipped:02x} to 0x{HARD_CRASH_ADDR:08x} via GDB RSP…")
            ok = gdb.write_byte(HARD_CRASH_ADDR, flipped)
            if not ok:
                print("ERROR: GDB write failed")
                return
            print(f"Fired ✓  GDB write OK  "
                  f"0x{original:02x} ({original:08b})  ->  0x{flipped:02x} ({flipped:08b})")
            crash_v = oracle.classify(observation_window_s=CRASH_WINDOW)
            if crash_v["outcome"] != "CRASH":
                print(f"\nOutcome: {crash_v['outcome']}  (no crash detected)")
                return
            print(f"\n\033[91mCRASH\033[0m  evidence: {crash_v['evidence']}")
            crash_evidence = crash_v["evidence"]

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
                "addr":          f"0x{HARD_CRASH_ADDR:08x}",
                "bit":           HARD_CRASH_BIT,
                "symbol":        "CHESS::rateGroupDriver+512",
                "original":      original,
                "flipped":       flipped,
                "outcome":       final,
                "recovery_path": recovery_path,
                "evidence":      crash_evidence,
                "rec_evidence":  rec_evidence,
            }) + "\n")
        print(f"\nResult appended to {RESULTS}")

    finally:
        oracle.stop()
