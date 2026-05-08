"""Phase: KERNEL_CRASH — persistent kernel text corruption via physical write."""

from __future__ import annotations

import json
import time

from nest_client.seu.injector import FaultInjectorClient, GdbMemWriter
from nest_client.client import NestClient

from ..config import (
    SOCK_PATH, RESULTS, NEST_URL,
    GDB_HOST, CONSOLE_LOG,
)
from ..helpers import _insn_delta, print_banner


def run_kernel_crash_phase(_args) -> None:
    """
    Two-step kernel corruption:
      1. Write UNDEFx4 to kernel entry phys 0x40008000 via QEMU monitor (writel).
         Survives CPU warm-reset because it hits physical RAM directly.
      2. Redirect vCPU PC to BSS NOP-slide so Phoenix loses its M4A heartbeat
         within ~30 s and M4A fires SOFT_REBOOT_A7A (1st reboot).
      After reboot the kernel hits our UNDEF immediately -> M4A fires a second
      SOFT_REBOOT_A7A -> HARD_CRASH confirmed.
    """
    M4A_FIRST_WINDOW  = 90.0
    M4A_SECOND_WINDOW = 90.0
    POST_REBOOT_WAIT  = 40.0

    KERNEL_ENTRY_PHYS = 0x40008000
    ARM_UNDEF         = 0xE7F000F0
    UNDEF_COUNT       = 4
    BAD_PC            = 0xC1000000

    print_banner("SEU Kernel-Crash Demo  Persistent kernel text corruption")

    gdb = GdbMemWriter(host=GDB_HOST, port=1234)

    print(f"\n  Kernel entry corruption  (phys 0x{KERNEL_ENTRY_PHYS:08x}, "
          f"{UNDEF_COUNT} × UNDEF 0x{ARM_UNDEF:08x})")
    text_writes = 0
    for i in range(UNDEF_COUNT):
        addr = KERNEL_ENTRY_PHYS + i * 4
        resp = gdb.monitor_command(f"writel 0x{addr:x} 0x{ARM_UNDEF:x}")
        ok = not resp.startswith("E")
        text_writes += int(ok)
        print(f"    phys 0x{addr:08x} -> 0x{ARM_UNDEF:08x}  {'✓' if ok else '✗'}")

    if text_writes == 0:
        print("\nERROR: all kernel text writes rejected.")
        return

    print(f"\n  Redirecting vCPU PC -> 0x{BAD_PC:08x} "
          f"(BSS NOP-slide kills Phoenix heartbeat)…")
    pc_ok, pc_before, pc_after = gdb.redirect_pc(BAD_PC)
    print(f"  PC before : 0x{pc_before:08x}")
    print(f"  PC after  : 0x{pc_after:08x}  "
          f"({'✓' if pc_ok else '✗ write failed PC may not have changed'})")

    target_name = (f"kernel text phys 0x{KERNEL_ENTRY_PHYS:08x} "
                   f"({text_writes} UNDEF words) + PC->0x{BAD_PC:08x}")
    print(f"\n  Inject : UNDEF×{text_writes} at kernel entry + PC redirect")
    print(f"  Effect : Phoenix heartbeat loss -> M4A SOFT_REBOOT -> boot hits "
          f"UNDEF -> M4A fires again -> HARD_CRASH")
    print()

    print(f"Kernel dead.  Waiting up to {M4A_FIRST_WINDOW:.0f}s for "
          f"M4A SOFT_REBOOT_A7A (Phoenix heartbeat loss)…")
    reboot1_seen = False
    try:
        with NestClient(url=NEST_URL) as _nc:
            try:
                _nc.wait_for_event(component="M4A", event="SOFT_REBOOT_A7A",
                                   timeout=M4A_FIRST_WINDOW)
                reboot1_seen = True
                print(f"  ✓ M4A fired SOFT_REBOOT_A7A  (1st reboot)")
            except Exception:
                print(f"  M4A did NOT fire within {M4A_FIRST_WINDOW:.0f}s.")
    except Exception as _e:
        print(f"  WARNING: NEST WebSocket error ({_e})")

    if not reboot1_seen:
        delta     = _insn_delta(5.0)
        cpu_alive = delta > 500_000
        final     = "CRASH_RECOVERED" if cpu_alive else "HARD_CRASH"
        explanation = (f"M4A did not fire; CPU {'alive' if cpu_alive else 'halted'} "
                       f"(delta={delta:,}).")
        print(f"\nFinal verdict: {final}\n  {explanation}")
        with RESULTS.open("a") as rf:
            rf.write(json.dumps({"target": target_name, "outcome": final,
                                 "evidence": explanation}) + "\n")
        print(f"Result appended to {RESULTS}")
        return

    print(f"\nWaiting {POST_REBOOT_WAIT:.0f}s for boot attempt…")
    time.sleep(POST_REBOOT_WAIT)

    print(f"Watching {M4A_SECOND_WINDOW:.0f}s for a SECOND SOFT_REBOOT_A7A "
          f"(would confirm kernel can't boot)…")
    reboot2_seen = False
    try:
        with NestClient(url=NEST_URL) as _nc:
            try:
                _nc.wait_for_event(component="M4A", event="SOFT_REBOOT_A7A",
                                   timeout=M4A_SECOND_WINDOW)
                reboot2_seen = True
                print("  ✓ M4A fired a SECOND SOFT_REBOOT_A7A kernel cannot boot!")
            except Exception:
                print("  No second M4A event kernel likely booted successfully.")
    except Exception as _e:
        print(f"  WARNING: NEST WebSocket error ({_e})")

    print("  Sampling CPU instruction rate…")
    time.sleep(2.0)
    delta_final = _insn_delta(5.0)
    cpu_running = delta_final > 500_000

    if reboot2_seen:
        final        = "HARD_CRASH"
        final_colour = "\033[91m"
        explanation  = (
            f"M4A fired twice: kernel entry UNDEF survived warm reset and "
            f"prevented boot. CPU {'running (stuck in ROM loop)' if cpu_running else 'halted'} "
            f"(delta={delta_final:,})."
        )
    elif cpu_running:
        final        = "CRASH_RECOVERED"
        final_colour = "\033[93m"
        explanation  = (
            f"CPU running after M4A reboot (delta={delta_final:,}). "
            "Kernel reinit overwrote our UNDEF (paging_init rebuilt page tables) "
            "or M4A issued a full RAM-clearing reset."
        )
    else:
        final        = "HARD_CRASH"
        final_colour = "\033[91m"
        explanation  = (
            f"CPU halted after M4A reboot (delta={delta_final:,}). "
            "Kernel hit UNDEF at entry and did not recover."
        )

    print(f"\nFinal verdict: {final_colour}{final}\033[0m")
    print(f"  {explanation}")

    with RESULTS.open("a") as rf:
        rf.write(json.dumps({
            "target":      target_name,
            "injected":    f"UNDEF×{text_writes} @ phys 0x{KERNEL_ENTRY_PHYS:08x}",
            "outcome":     final,
            "evidence":    explanation,
            "reboot_1":    reboot1_seen,
            "reboot_2":    reboot2_seen,
            "delta_final": delta_final,
        }) + "\n")
    print(f"Result appended to {RESULTS}")

    # Reset VM to clear physical RAM corruption so subsequent tests can run.
    print(f"\nResetting VM to clear kernel corruption (system_reset)…")
    gdb.monitor_command("system_reset")
    print("  system_reset sent.  Waiting for CHESS to boot (up to 120s)…")
    _boot_deadline = time.monotonic() + 120.0
    _booted = False
    if CONSOLE_LOG and CONSOLE_LOG.exists():
        _prev_size = CONSOLE_LOG.stat().st_size
        while time.monotonic() < _boot_deadline:
            time.sleep(3.0)
            try:
                _cur_size = CONSOLE_LOG.stat().st_size
                if _cur_size != _prev_size:
                    _prev_size = _cur_size
                    if "RateGroupStarted" in CONSOLE_LOG.read_text(errors="replace"):
                        print("  CHESS booted ✓")
                        _booted = True
                        break
            except OSError:
                pass
    if not _booted:
        print("  (could not confirm boot — proceed after CHESS is ready)")
