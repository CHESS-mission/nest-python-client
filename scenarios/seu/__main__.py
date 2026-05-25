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
from seu.phases.ci import run_ci
from seu.phases.interactive import run_interactive
from seu.phases.state_machine import run_state_machine
from seu.phases.ci_debug import run_ci_debug


def main() -> None:
    parser = argparse.ArgumentParser(description="CHESS SEU fault injection scenario")
    parser.add_argument("--manual",       action="store_true",
                        help="Phase 1: run the hand-crafted MANUAL_TARGETS list")
    parser.add_argument("--sweep",        action="store_true",
                        help="Phase 2: automated ELF sweep (size-proportional random)")
    parser.add_argument("--ci",           action="store_true",
                        help="CI regression check: fixed quota per CHESS:: component")
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
    parser.add_argument("--state-machine", action="store_true",
                        help="Pairwise invariant: inject into EventAction m_state (32 bit flips)")
    parser.add_argument("--ci-debug",     action="store_true",
                        help="CI oracle pipeline on user-specified targets (--targets / --targets-file)")

    parser.add_argument("--delay",       type=int,   default=1_000_000,
                        help="Instructions before each injection (default 1M)")
    parser.add_argument("--window",      type=float, default=5.0,
                        help="Oracle observation window in seconds (default 5)")
    parser.add_argument("--all-symbols", action="store_true",
                        help="Sweep all symbols, not just FPrime candidates")
    parser.add_argument("--filter",      metavar="REGEX",
                        help="Only inject into symbols matching this regex (sweep only)")
    parser.add_argument("--max-targets", type=int,   default=20,
                        help="Number of sweep targets (default 20)")
    parser.add_argument("--random",      action="store_true",
                        help="Pick sweep targets randomly (size-proportional) instead of sequentially")
    parser.add_argument("--seed",        type=int,   default=42,
                        help="Random seed for --random / --ci (default 42)")

    # CI-specific options
    parser.add_argument("--quota",     type=int,   default=60,
                        help="--ci: total injections distributed proportionally across components (default 60)")
    parser.add_argument("--threshold", type=float, default=0.10,
                        help="--ci: masked-rate increase that triggers failure (default 0.10)")
    parser.add_argument("--baseline",  metavar="RUN_ID",
                        help="--ci: DB run_id (or prefix) to compare against")
    parser.add_argument("--ci-filter", metavar="PREFIX", default="CHESS::",
                        help="--ci: symbol prefix to include (default CHESS::)")
    parser.add_argument("--ci-exclude", metavar="REGEX", default="ConfigObjects|cmdSeq",
                        help="--ci: exclude component names matching this regex "
                             "(default: ConfigObjects=init-only dead data, cmdSeq=idle with no sequence running)")
    parser.add_argument("--vtable-skip", type=int, default=64, metavar="N",
                        help="--ci / --sweep: skip the first N bytes of each component "
                             "symbol when sampling.  Default 64 excludes C++ vtable pointers "
                             "and port-connection fields which would otherwise dominate the "
                             "campaign with guaranteed CRASH-class outcomes.  Use "
                             "--vtable-skip 0 to include those targets — recommended for "
                             "radiation-realistic --sweep runs where you want CRASH outcomes "
                             "to appear in the distribution.")
    # --ci-debug target specs
    parser.add_argument("--targets", nargs="+", metavar="SPEC",
                        help="--ci-debug: space-separated target specs. "
                             "Formats: 0xADDR:BIT[,BIT]  SYMBOL:BIT  SYMBOL::FIELD:BIT  "
                             "(BIT may be comma-separated, e.g. 0x000c0930:0,3,7)")
    parser.add_argument("--targets-file", metavar="FILE",
                        help="--ci-debug: file with one target spec per line "
                             "(# comments allowed; in Docker the path must be inside the container)")
    parser.add_argument("--golden-duration", type=float, default=10.0,
                        help="--ci-debug: seconds to sample CHESS's clean event stream "
                             "before injections start (default 10)")

    args = parser.parse_args()

    if not any([args.manual, args.sweep, args.ci, args.ci_debug, args.interactive,
                args.hard_crash, args.kernel_crash, args.detected,
                args.redundant, args.state_machine]):
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

    if args.ci_debug:
        run_ci_debug(args)
    elif args.interactive:
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
        # --sweep now routes through the same campaign engine as --ci,
        # with the symbol filter cleared.  This gives a radiation-like
        # uniform-per-byte sample across all .bss/.data symbols while
        # benefiting from Layer-5 / MASKED_CRITICAL / stable-ELF remap /
        # byte-restore.  The legacy run_automated_sweep is retained but
        # no longer the default it's missing the new pipeline features.
        run_ci(args)
    elif args.ci:
        run_ci(args)
    elif args.state_machine:
        run_state_machine(args)
    else:
        run_manual_phase(args)


if __name__ == "__main__":
    main()
