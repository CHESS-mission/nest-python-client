#!/usr/bin/env python3
"""
NEST scenario for SEU (Single Event Upset) fault injection.

Run as a package directory:
    python3 scenarios/seu [--manual|--sweep|--detected|--hard-crash|--kernel-crash|--interactive]

Environment variables
---------------------
FAULT_INJECT_SOCK   Path to plugin control socket  (default /tmp/fi.sock)
CHESS_ELF_PATH      Path to CHESS ELF binary
NEST_URL            NEST WebSocket URL              (default ws://localhost:3000/ws)
NEST_GDB_HOST       GDB stub hostname               (default localhost)
NEST_DOCKER         Set to 1 for Docker/TCG mode
NEST_CONSOLE_LOG    Path to hvc0 file-chardev log
SEU_RESULTS         Path to JSONL results file      (default /tmp/seu_results.jsonl)
"""

from __future__ import annotations

import os
import sys

# When invoked as `python3 /path/to/seu` (directory), Python sets __package__=None
# and does not add the parent directory to sys.path, breaking relative imports.
# Insert the parent here so `seu` is importable as a package before any imports.
_pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _pkg_parent not in sys.path:
    sys.path.insert(0, _pkg_parent)

import argparse

from nest_client.client import NestClient
from nest_client.seu.injector import PtyOracle

from seu.config import (
    _docker_mode, PTY_LOG, NEST_URL,
    CONSOLE_LOG, CONSOLE_HOST, CONSOLE_PORT,
)
from seu.helpers import set_nominal_environment, wait_for_chess_ready
from seu.phases.manual import run_manual_phase
from seu.phases.detected import run_detected_phase
from seu.phases.hard_crash import run_hard_crash_phase
from seu.phases.kernel_crash import run_kernel_crash_phase
from seu.phases.sweep import run_automated_sweep
from seu.phases.interactive import run_interactive


def main() -> None:
    parser = argparse.ArgumentParser(description="CHESS SEU fault injection scenario")
    parser.add_argument("--manual",       action="store_true",
                        help="Phase 1: run the hand-crafted MANUAL_TARGETS list")
    parser.add_argument("--sweep",        action="store_true",
                        help="Phase 2: automated ELF sweep")
    parser.add_argument("--interactive",  action="store_true",
                        help="Interactive mode (type inject commands)")
    parser.add_argument("--hard-crash",   action="store_true",
                        help="Demo: vtable bit-flip -> CRASH_RECOVERED (F' restarts)")
    parser.add_argument("--kernel-crash", action="store_true",
                        help="Demo: kernel text corruption -> HARD_CRASH (survives reboot)")
    parser.add_argument("--detected",     action="store_true",
                        help="Demo: cycleCount injection -> DETECTED (F' logs WARNING)")
    parser.add_argument("--redundant",    action="store_true",
                        help="Redundant topology: watch CPU_B for M4/Mux switchover after CRASH")

    parser.add_argument("--delay",       type=int,   default=1_000_000,
                        help="Instructions before each injection (default 1M)")
    parser.add_argument("--window",      type=float, default=5.0,
                        help="Oracle observation window in seconds (default 5)")
    parser.add_argument("--all-symbols", action="store_true",
                        help="Sweep all symbols, not just FPrime candidates")
    parser.add_argument("--filter",      metavar="REGEX",
                        help="Only inject into symbols matching this regex")
    parser.add_argument("--max-targets", type=int,   default=20,
                        help="Number of sweep targets (default 20)")
    parser.add_argument("--random",      action="store_true",
                        help="Pick sweep targets randomly instead of sequentially")
    parser.add_argument("--seed",        type=int,   default=42,
                        help="Random seed for --random (default 42)")

    args = parser.parse_args()

    if not any([args.manual, args.sweep, args.interactive,
                args.hard_crash, args.kernel_crash, args.detected]):
        args.manual = True

    # Pre-connect to the CHESS console when using a TCP chardev (simple topology).
    # QEMU blocks boot until a client connects, so we connect here to unblock it
    # before calling set_nominal_environment / wait_for_chess_ready.
    _console_oracle = None
    if args.detected and _docker_mode and CONSOLE_LOG is None and CONSOLE_HOST != "localhost":
        _console_oracle = PtyOracle((CONSOLE_HOST, CONSOLE_PORT))
        _console_oracle.start()
        print(f"Console oracle pre-connected at {CONSOLE_HOST}:{CONSOLE_PORT} "
              f"(unblocks QEMU wait=on, PORT_OPEN=true from boot)")

    set_nominal_environment(NEST_URL)

    if _docker_mode:
        print(f"Checking NEST simulation status at {NEST_URL} …")
        try:
            with NestClient(url=NEST_URL) as _nc:
                _nc.wait_for_status("running", timeout=120.0)
            print("  NEST status: running  ✓")
        except Exception as _e:
            print(f"  WARNING: could not confirm NEST status ({_e}) proceeding anyway.")
    else:
        wait_for_chess_ready(PTY_LOG, timeout=120.0)

    if _docker_mode or args.redundant:
        print("Resetting M4B to CPU_A after CHESS boot…")
        try:
            with NestClient(url=NEST_URL) as _nc:
                _nc.send_command("M4B", "switch_back_to_a7a", "{}")
            print("  M4B -> A7A ✓")
        except Exception as _e:
            print(f"  WARNING: could not reset M4B ({_e})")

    if args.interactive:
        run_interactive(args)
    elif args.kernel_crash:
        run_kernel_crash_phase(args)
    elif args.hard_crash:
        run_hard_crash_phase(args)
    elif args.detected:
        run_detected_phase(args, pre_oracle=_console_oracle)
        if _console_oracle:
            _console_oracle.stop()
    elif args.sweep:
        run_automated_sweep(args)
    else:
        run_manual_phase(args)


if __name__ == "__main__":
    main()
