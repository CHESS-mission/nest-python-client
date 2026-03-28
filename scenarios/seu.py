#!/usr/bin/env python3
"""
seu.py — NEST scenario for SEU (Single Event Upset) fault injection.

Run from the nest-python-client/ directory:

    python3 scenarios/seu.py                # Phase 1 manual targets (default)
    python3 scenarios/seu.py --sweep        # Phase 2 automated ELF sweep
    python3 scenarios/seu.py --interactive  # Interactive injector CLI

── What this scenario does ──────────────────────────────────────────────────

Phase 1 — Manual SEU (default or --manual):
  Runs a predefined list of bit-flip specs derived from manual analysis
  of the CHESS binary.  Each injection is logged and the PTY oracle
  classifies FPrime's response.

Phase 2 — Automated sweep (--sweep):
  Uses elf_analyzer to enumerate every writable FPrime state variable,
  then injects every bit in those variables in sequence.  Results are
  written to /tmp/seu_results.jsonl.

── Prerequisites ────────────────────────────────────────────────────────────
  1.  NEST server must be running with the SEU topology:
          nest/target/debug/nest-server --topology nest/examples/topology_seu.yaml
  2.  The fault_inject.so plugin must be built (nest/plugins/) and loaded
      by QEMU automatically via the topology options.
  3.  CHESS binary must be running inside QEMU.
  4.  The QEMU serial PTY must be active at /tmp/qemu-serial-pty (or
      set NEST_PTY_LOG to point to the tailed log file).

── Environment variables ────────────────────────────────────────────────────
  NEST_PTY_LOG      Path to the PTY log file being tailed by run_seu_test.sh
                    (falls back to /tmp/qemu-serial-pty for direct reads).
  FAULT_INJECT_SOCK Path to the plugin control socket (default /tmp/fi.sock).
  SEU_RESULTS       Path to the JSONL results file (default /tmp/seu_results.jsonl).
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from nest_client.seu.injector import (
    FaultInjectorClient,
    InjectionSpec,
    SEUCampaign,
    CampaignConfig,
    PtyOracle,
    restart_chess_in_qemu,
)
from nest_client.client import NestClient
from nest_client.types import EnvVarType
from nest_client.seu.result_db import SEUResultDB

# ── Paths ────────────────────────────────────────────────────────────────────

# SP root is three levels up: scenarios/ → nest-python-client/ → SP/
_SP = Path(__file__).resolve().parent.parent.parent

ELF_PATH   = (_SP / "CHESS-FS" / "build-fprime-automatic-arm-hf-linux"
              / "bin" / "arm-hf-linux" / "CHESS_Pathfinder0FS")

SOCK_PATH  = Path(os.environ.get("FAULT_INJECT_SOCK", "/tmp/fi.sock"))
RESULTS    = Path(os.environ.get("SEU_RESULTS",       "/tmp/seu_results.jsonl"))
SEU_DB     = Path(os.environ.get("SEU_DB", str(_SP / "seu_history.db")))

# PTY log: prefer the file written by run_seu_test.sh (avoids PTY read contention)
_pty_env   = os.environ.get("NEST_PTY_LOG", "")
PTY_LOG    = Path(_pty_env) if _pty_env else Path("/tmp/qemu-serial-pty")

# CPU_B PTY log (redundant topology only)
_pty_env_b = os.environ.get("NEST_PTY_LOG_B", "")
PTY_LOG_B  = Path(_pty_env_b) if _pty_env_b else None


# ── Phase 1: manually identified SEU candidates ───────────────────────────────
#
# Targets are resolved dynamically from the ELF at scenario start using
# elf_analyzer.  This ensures addresses remain correct after any rebuild.
#
# Strategy per symbol:
#   obcSensorsManager — DWARF field-named targets (cross-version stable by name)
#                       + mid-object sampling (FPrime infra: throttle counters)
#   rateGroupDriver   — offset sampling past the vtable region
#   .text functions   — put first so crash fires early in the queue
#
# To inspect available fields:
#   cd nest-python-client
#   python3 -m nest_client.seu.elf_analyzer --expand --filter obcSensorsManager \
#       ../CHESS-FS/build-fprime-automatic-arm-hf-linux/bin/arm-hf-linux/CHESS_Pathfinder0FS

def _build_manual_targets(elf_path: Path,
                           delay: int = 10_000_000) -> list[InjectionSpec]:
    """
    Resolve MANUAL_TARGETS dynamically from the ELF symbol table + DWARF.

    .text function targets are placed first so crashes fire early rather than
    at the end of a long data-injection queue.
    """
    from nest_client.seu import elf_analyzer  # lazy import (needs pyelftools)

    if not elf_path.exists():
        print(f"WARNING: ELF not found at {elf_path} — MANUAL_TARGETS will be empty.")
        return []

    print(f"Resolving MANUAL_TARGETS from ELF: {elf_path.name}…")
    symbols = elf_analyzer.analyze(elf_path)

    def find_sym(pattern: str, section: str | None = None):
        """First symbol whose demangled name contains pattern.

        If section is given, only match symbols in that section.
        For data targets pass section='.bss' or '.data' to avoid accidentally
        matching method names that contain the same pattern.
        """
        for s in symbols:
            if pattern in s.demangled:
                if section is None or s.section == section:
                    return s
        return None

    specs_text: list[InjectionSpec] = []
    specs_data: list[InjectionSpec] = []

    # ── .text function targets ────────────────────────────────────────────────
    # Put these first so a crash happens at injection 1-2, not at the end.
    for func_pattern, label in [
        ('checkSensorHealth', 'OBCSensorsManager::checkSensorHealth'),
        ('pollIMU',           'OBCSensorsManager::pollIMU'),
    ]:
        sym = find_sym(func_pattern)
        if sym and sym.section == '.text':
            specs_text.append(InjectionSpec(addr=sym.address, bit=0, delay=delay))
            print(f"  [.text] {label} @ 0x{sym.address:08x}")
        else:
            print(f"  WARNING: .text symbol '{func_pattern}' not found")

    # ── obcSensorsManager ─────────────────────────────────────────────────────
    obc = find_sym('obcSensorsManager', section='.bss')
    if obc:
        print(f"  [bss]   obcSensorsManager @ 0x{obc.address:08x}  size={obc.size}")
        # DWARF field-named targets — stable across rebuilds as long as the
        # field name exists in the class.
        field_map = elf_analyzer.expand_symbol_fields(elf_path, [obc])
        fields = field_map.get(obc.name, [])
        _named = {'imuEnabled', 'gyroEnabled', 'accelEnabled', 'magMeasured',
                  'magConsecutiveFailures', 'magRecoveryCycleCount'}
        hit = set()
        for fi in fields:
            if fi.field_name in _named:
                for bit in (0, 3):
                    a = obc.address + fi.offset
                    specs_data.append(InjectionSpec(addr=a, bit=bit, delay=delay))
                hit.add(fi.field_name)
                print(f"    +{fi.offset:<6} {fi.field_name} @ 0x{obc.address + fi.offset:08x}")
        if not hit:
            print("    (no named DWARF fields matched — DWARF may be missing; "
                  "rebuild with RelWithDebInfo)")
        # Sampling targets for FPrime infra (throttle counters, tlm buffers)
        for off in (512, 1024, 2048, 2560):
            if off < obc.size:
                a = obc.address + off
                specs_data.append(InjectionSpec(addr=a, bit=0, delay=delay))
                print(f"    +{off:<6} (sampling) @ 0x{a:08x}")
    else:
        print("  WARNING: obcSensorsManager not found in symbol table")

    # ── rateGroupDriver ───────────────────────────────────────────────────────
    rgd = find_sym('rateGroupDriver', section='.bss')
    if rgd:
        print(f"  [bss]   rateGroupDriver  @ 0x{rgd.address:08x}  size={rgd.size}")
        for off in (128, 256, 512):
            if off < rgd.size:
                a = rgd.address + off
                specs_data.append(InjectionSpec(addr=a, bit=0, delay=delay))
                print(f"    +{off:<6} (sampling) @ 0x{a:08x}")
    else:
        print("  WARNING: rateGroupDriver not found in symbol table")

    specs = specs_text + specs_data
    print(f"  → {len(specs)} injection specs  "
          f"({len(specs_text)} .text, {len(specs_data)} data)")
    return specs


# Resolved at scenario start (after ELF path is known) — see run_manual_phase()
MANUAL_TARGETS: list[InjectionSpec] = []


# ── Helpers ───────────────────────────────────────────────────────────────────

def wait_for_chess_ready(pty_log: Path, timeout: float = 120.0) -> bool:
    """
    Wait until the CHESS binary logs "Registered with the Communications Task"
    or any other line that indicates it has fully started.
    """
    print(f"Waiting for CHESS binary to be ready (watching {pty_log})…")
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
                    if any(kw in decoded for kw in [
                        "CHESS_Pathfinder0FS",
                        "OpCodeRegistered",
                        "Starting HealthImpl",
                        "Registered with",
                        "all components ready",
                        "rate group",
                        "SENSOR_POLL_CYCLE",
                    ]):
                        print(f"  → CHESS ready: {decoded.strip()}")
                        return True
        except (FileNotFoundError, OSError):
            time.sleep(0.5)

    print("WARNING: Timed out waiting for CHESS to be ready. Proceeding anyway.")
    return False


def restart_chess(pty_log: Path, timeout: float = 120.0) -> bool:
    """Restart CHESS inside QEMU via the PTY."""
    return restart_chess_in_qemu(pty_log, timeout=timeout)


def wait_for_cpu_b_takeover(pty_log_b: Path, timeout: float = 60.0) -> float | None:
    """
    Watch CPU_B's PTY log for FPrime startup events, indicating the Mux
    has switched over to CPU_B after CPU_A crashed.

    Returns the elapsed seconds until switchover was detected, or None on timeout.
    """
    if not pty_log_b or not pty_log_b.exists():
        time.sleep(1.0)
        if not pty_log_b or not pty_log_b.exists():
            return None

    _READY_KEYWORDS = [
        "CHESS_Pathfinder0FS",
        "OpCodeRegistered",
        "Starting HealthImpl",
        "Registered with",
        "SENSOR_POLL_CYCLE",
        "rate group",
    ]

    print(f"  Watching CPU_B log for takeover: {pty_log_b}", flush=True)
    t0 = time.monotonic()
    deadline = t0 + timeout

    while time.monotonic() < deadline:
        try:
            with pty_log_b.open("r", errors="replace") as f:
                while time.monotonic() < deadline:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    if any(kw in line for kw in _READY_KEYWORDS):
                        elapsed = time.monotonic() - t0
                        print(f"  CPU_B active after {elapsed:.1f}s: {line.strip()}",
                              flush=True)
                        return elapsed
        except (FileNotFoundError, OSError):
            time.sleep(0.5)

    print(f"  CPU_B did not take over within {timeout:.0f}s.", flush=True)
    return None


def set_nominal_environment(nest_url: str = "ws://localhost:3000/ws") -> None:
    """
    Push nominal sensor environment variables to NEST before starting injections.

    Values mirror sensors_fuzz.py env_ramp() steady-state targets (after ramp):
      temp    = 35.0 °C
      accel   = [0.5, 0.5, 9.8]  (non-zero g — realistic LEO free-fall + noise)
      omega   = [0.1, 0.2, 0.3]  dps
      B_field = [MAG_OFFSET + MAG_SENSITIVITY*0.3,
                 MAG_OFFSET + MAG_SENSITIVITY*0.2,
                 MAG_OFFSET + MAG_SENSITIVITY*0.1]
              → non-zero converted uT, non-zero raw counts, passes both the
                "all zeros or all FF" raw-register check AND any app-level checks
    """
    import numpy as np
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
              "Sensor readings may be all-zero — results will be unreliable.")


def print_banner(title: str) -> None:
    w = 70
    print("\n" + "─" * w)
    print(f"  {title}")
    print("─" * w)


# ── Scenario runners ──────────────────────────────────────────────────────────

def run_manual_phase(args) -> None:
    print_banner("SEU Fault Injection — Phase 1 (Manual Targets)")

    elf = ELF_PATH if ELF_PATH.exists() else None
    targets = _build_manual_targets(ELF_PATH, delay=args.delay) if elf else MANUAL_TARGETS

    if not targets:
        print(
            "ERROR: no injection targets could be resolved.\n"
            "  Ensure the ELF exists and was built with RelWithDebInfo:\n\n"
            f"    {ELF_PATH}\n\n"
            "  Then re-run.  See fault_injection/run_seu_test.sh --regen."
        )
        return
    if elf is None:
        print(f"WARNING: ELF not found at {ELF_PATH}. Proceeding without symbol info.")

    import json
    db = SEUResultDB(SEU_DB)
    run_id = db.start_run(
        elf_path=ELF_PATH if elf else Path("/dev/null"),
        topology=str(Path(os.environ.get("TOPOLOGY_PATH", "topology_seu.yaml")).name),
        notes="manual phase",
    ) if elf else None

    oracle = PtyOracle(PTY_LOG)
    oracle.start()

    try:
        with FaultInjectorClient(SOCK_PATH) as fi:
            cnt = fi.get_count()
            print(f"Plugin connected. Current insn count: {cnt:,}")

            for i, spec in enumerate(targets):
                print(f"\n[{i+1}/{len(targets)}] "
                      f"addr=0x{spec.addr:08x}  bit={spec.bit}  "
                      f"delay={spec.delay:,} insns")

                # Drain stale oracle events before every injection so that
                # events from previous boots cannot bleed into this verdict.
                oracle.drain()

                trigger = fi.inject_mem(addr=spec.addr, bit=spec.bit,
                                        delay=spec.delay)
                print(f"  Scheduled at insn {trigger:,}. Waiting for fire…")

                plugin_resp = fi.wait_for_result(timeout=120.0, trigger_insn=trigger)
                if plugin_resp is None:
                    print("  TIMEOUT: injection did not fire (delay too large?)")
                    continue

                orig    = plugin_resp.get('original', 0)
                flipped = plugin_resp.get('flipped', 0)
                print(f"  Fired: write={'OK' if plugin_resp['success'] else 'FAIL'} "
                      f"0x{orig:02x} → 0x{flipped:02x}  "
                      f"(bit {spec.bit}: {orig:08b} → {flipped:08b})")

                verdict = oracle.classify(observation_window_s=5.0)
                outcome = verdict["outcome"]

                _colour = {"CRASH": "\033[91m", "DETECTED": "\033[93m",
                           "MASKED": "\033[92m"}.get(outcome, "")
                _reset  = "\033[0m"
                print(f"  Outcome: {_colour}{outcome}{_reset}")
                if verdict["evidence"]:
                    print(f"  Evidence: {verdict['evidence']}")
                if verdict["last_events"]:
                    print(f"  Last FS events ({len(verdict['last_events'])}):")
                    for ev in verdict["last_events"]:
                        print(f"    {ev}")
                else:
                    print("  Last FS events: (none — FS may be silent)")

                record = {
                    **plugin_resp,
                    "addr":       f"0x{spec.addr:08x}",
                    "bit":        spec.bit,
                    "outcome":    outcome,
                    "evidence":   verdict["evidence"],
                }
                with RESULTS.open("a") as rf:
                    rf.write(json.dumps(record) + "\n")

                if run_id:
                    db.record(
                        run_id=run_id,
                        addr=spec.addr,
                        bit=spec.bit,
                        original=orig,
                        flipped=flipped,
                        write_ok=plugin_resp.get("success", False),
                        outcome=outcome,
                        evidence=verdict["evidence"],
                        insn_count=plugin_resp.get("insn_count"),
                        elf_path=elf,
                    )

                # Restart CHESS after every injection (not just CRASH) so that
                # each test starts from a clean binary state with no accumulated
                # corruption.  Drain the oracle after restart so events from the
                # crash or boot sequence don't bleed into the next verdict.
                if outcome == "CRASH" and args.redundant and PTY_LOG_B:
                    elapsed = wait_for_cpu_b_takeover(PTY_LOG_B, timeout=60.0)
                    if elapsed is not None:
                        print(f"  \033[92mCPU_B took over in {elapsed:.1f}s\033[0m",
                              flush=True)
                        import json
                        records = RESULTS.read_text().strip().splitlines()
                        if records:
                            last = json.loads(records[-1])
                            last["cpu_b_takeover_s"] = round(elapsed, 2)
                            last["outcome"] = "CRASH_RECOVERED"
                            records[-1] = json.dumps(last)
                            RESULTS.write_text("\n".join(records) + "\n")
                    else:
                        print("  \033[91mWARNING: CPU_B did not take over!\033[0m",
                              flush=True)
                else:
                    print("  Restarting CHESS for clean state…", flush=True)
                    restarted = restart_chess(PTY_LOG, timeout=120.0)
                    if restarted:
                        print("  FS back online — settling 3s…", flush=True)
                        time.sleep(3.0)
                        oracle.drain()
                    else:
                        print("  WARNING: FS did not restart within 120s.",
                              flush=True)
    finally:
        oracle.stop()

    print(f"\nResults appended to {RESULTS}")

    if run_id:
        db.print_run_summary(run_id)
        items = db.compare(run_id)
        db.print_review_queue(items)
        db.close()


def run_automated_sweep(args) -> None:
    print_banner("SEU Fault Injection — Phase 2 (Automated Sweep)")

    if not ELF_PATH.exists():
        sys.exit(f"ERROR: ELF not found: {ELF_PATH}")

    cfg = CampaignConfig(
        socket_path          = SOCK_PATH,
        elf_path             = ELF_PATH,
        pty_log_path         = PTY_LOG,
        delay_insn           = args.delay,
        observation_window_s = args.window,
        candidates_only      = not args.all_symbols,
        filter_re            = args.filter,
        results_path         = RESULTS,
    )

    campaign = SEUCampaign(cfg)
    results  = campaign.run_sweep(max_targets=args.max_targets)
    campaign.print_summary()

    print(f"\nResults written to {RESULTS}")
    return results


def run_interactive(_args) -> None:
    """Interactive mode: query the plugin and inject manually from the CLI."""
    print_banner("SEU Fault Injection — Interactive Mode")

    with FaultInjectorClient(SOCK_PATH) as fi:
        cnt = fi.get_count()
        print(f"Plugin connected. insn_count = {cnt:,}")
        print("Commands:  count | inject <addr_hex> <bit> <delay> | result | clear | quit")
        print()

        while True:
            try:
                line = input("fi> ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not line:
                continue
            parts = line.split()
            cmd = parts[0].lower()

            if cmd in ("q", "quit", "exit"):
                break
            elif cmd == "count":
                print(f"insn_count = {fi.get_count():,}  pending = {fi.is_pending()}")
            elif cmd == "result":
                import json
                r = fi.last_result()
                print(json.dumps(r, indent=2) if r else "No result yet.")
            elif cmd == "clear":
                fi.clear()
                print("Cleared.")
            elif cmd == "inject":
                if len(parts) < 4:
                    print("Usage: inject <addr_hex> <bit 0-7> <delay_insns>")
                    continue
                try:
                    addr  = int(parts[1], 0)
                    bit   = int(parts[2])
                    delay = int(parts[3])
                except ValueError as e:
                    print(f"Parse error: {e}")
                    continue
                trigger = fi.inject_mem(addr=addr, bit=bit, delay=delay)
                print(f"Scheduled at insn {trigger:,}. Waiting…")
                import json
                r = fi.wait_for_result(timeout=60.0)
                print(json.dumps(r, indent=2) if r else "Timed out.")
            else:
                print(f"Unknown command: {cmd}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CHESS SEU fault injection scenario"
    )
    parser.add_argument("--manual", action="store_true",
                        help="Phase 1: run the hand-crafted MANUAL_TARGETS list")
    parser.add_argument("--sweep", action="store_true",
                        help="Phase 2: automated ELF sweep")
    parser.add_argument("--interactive", action="store_true",
                        help="Interactive mode (type inject commands)")
    parser.add_argument("--redundant", action="store_true",
                        help="Redundant topology: watch CPU_B for M4/Mux switchover after CRASH")

    # Sweep options
    parser.add_argument("--delay", type=int, default=10_000_000,
                        help="Instructions before each injection (default 5M)")
    parser.add_argument("--window", type=float, default=5.0,
                        help="Oracle observation window in seconds (default 15)")
    parser.add_argument("--all-symbols", action="store_true",
                        help="Sweep all symbols, not just FPrime candidates")
    parser.add_argument("--filter", metavar="REGEX",
                        help="Only inject into symbols matching this regex")
    parser.add_argument("--max-targets", type=int,
                        help="Limit sweep to first N targets")

    args = parser.parse_args()

    if not any([args.manual, args.sweep, args.interactive]):
        args.manual = True

    set_nominal_environment()
    wait_for_chess_ready(PTY_LOG)

    if args.interactive:
        run_interactive(args)
    elif args.sweep:
        run_automated_sweep(args)
    else:
        run_manual_phase(args)


if __name__ == "__main__":
    main()
