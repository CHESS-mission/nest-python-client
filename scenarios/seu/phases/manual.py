"""Phase 1: manual SEU injection targets."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from nest_client.seu.injector import (
    FaultInjectorClient,
    GdbMemWriter,
    InjectionSpec,
    PtyOracle,
)
from nest_client.seu.result_db import SEUResultDB

from ..config import (
    ELF_PATH, SOCK_PATH, RESULTS, SEU_DB,
    _docker_mode, PTY_LOG, PTY_LOG_B, GDB_HOST,
)
from ..helpers import (
    _classify, print_banner, restart_chess, wait_for_cpu_b_takeover,
)


MANUAL_TARGETS: list[InjectionSpec] = []


def _build_manual_targets(elf_path: Path, delay: int = 10_000_000) -> list[InjectionSpec]:
    """
    Resolve injection targets dynamically from the ELF symbol table + DWARF.

    .text function targets are placed first so crashes fire early rather than
    at the end of a long data-injection queue.
    """
    from nest_client.seu import elf_analyzer

    if not elf_path.exists():
        print(f"WARNING: ELF not found at {elf_path} MANUAL_TARGETS will be empty.")
        return []

    print(f"Resolving MANUAL_TARGETS from ELF: {elf_path.name}…")
    symbols = elf_analyzer.analyze(elf_path)

    def find_sym(pattern: str, section: str | None = None):
        for s in symbols:
            if pattern in s.demangled:
                if section is None or s.section == section:
                    return s
        return None

    specs_text: list[InjectionSpec] = []
    specs_data: list[InjectionSpec] = []

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

    obc = find_sym('obcSensorsManager', section='.bss')
    if obc:
        print(f"  [bss]   obcSensorsManager @ 0x{obc.address:08x}  size={obc.size}")
        field_map = elf_analyzer.expand_symbol_fields(elf_path, [obc])
        fields = field_map.get(obc.name, [])
        _named = {'imuEnabled', 'gyroEnabled', 'accelEnabled', 'magMeasured',
                  'magConsecutiveFailures', 'magRecoveryCycleCount'}
        hit = set()
        for fi in fields:
            if fi.field_name in _named:
                for bit in (0, 3):
                    specs_data.append(InjectionSpec(addr=obc.address + fi.offset, bit=bit, delay=delay))
                hit.add(fi.field_name)
                print(f"    +{fi.offset:<6} {fi.field_name} @ 0x{obc.address + fi.offset:08x}")
        if not hit:
            print("    (no named DWARF fields matched — rebuild with RelWithDebInfo)")
        for off in (512, 1024, 2048, 2560):
            if off < obc.size:
                specs_data.append(InjectionSpec(addr=obc.address + off, bit=0, delay=delay))
                print(f"    +{off:<6} (sampling) @ 0x{obc.address + off:08x}")
    else:
        print("  WARNING: obcSensorsManager not found in symbol table")

    rgd = find_sym('rateGroupDriver', section='.bss')
    if rgd:
        print(f"  [bss]   rateGroupDriver  @ 0x{rgd.address:08x}  size={rgd.size}")
        for off in (128, 256, 512):
            if off < rgd.size:
                specs_data.append(InjectionSpec(addr=rgd.address + off, bit=0, delay=delay))
                print(f"    +{off:<6} (sampling) @ 0x{rgd.address + off:08x}")
    else:
        print("  WARNING: rateGroupDriver not found in symbol table")

    specs = specs_text + specs_data
    print(f"  -> {len(specs)} injection specs  ({len(specs_text)} .text, {len(specs_data)} data)")
    return specs


def run_manual_phase(args) -> None:
    print_banner("SEU Fault Injection Phase 1 (Manual Targets)")

    elf = ELF_PATH if ELF_PATH.exists() else None
    targets = _build_manual_targets(ELF_PATH, delay=args.delay) if elf else MANUAL_TARGETS

    if not targets:
        print(
            "ERROR: no injection targets could be resolved.\n"
            "  Ensure the ELF exists and was built with RelWithDebInfo:\n\n"
            f"    {ELF_PATH}\n\n"
            "  Then re-run."
        )
        return
    if elf is None:
        print(f"WARNING: ELF not found at {ELF_PATH}. Proceeding without symbol info.")

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

                oracle.drain()

                trigger = fi.inject_mem(addr=spec.addr, bit=spec.bit, delay=spec.delay)
                print(f"  Scheduled at insn {trigger:,}. Waiting for fire…")

                plugin_resp = fi.wait_for_result(timeout=120.0, trigger_insn=trigger)
                if plugin_resp is None:
                    print("  TIMEOUT: injection did not fire (delay too large?)")
                    continue

                orig    = plugin_resp.get('original', 0)
                flipped = plugin_resp.get('flipped', 0)
                wrote   = plugin_resp.get('success', False)

                if not wrote and _docker_mode and flipped != orig:
                    try:
                        gdb = GdbMemWriter(host=GDB_HOST, port=1234)
                        wrote = gdb.write_byte(spec.addr, flipped)
                        print(f"  GDB write: 0x{flipped:02x} -> {'OK' if wrote else 'FAIL'}")
                    except Exception as _e:
                        print(f"  GDB write: FAIL ({_e})")

                print(f"  Fired: write={'OK' if wrote else 'FAIL'} "
                      f"0x{orig:02x} -> 0x{flipped:02x}  "
                      f"(bit {spec.bit}: {orig:08b} -> {flipped:08b})")

                verdict = _classify(fi, oracle, window_s=5.0)
                outcome = verdict["outcome"]

                # Restore the original byte to prevent corruption accumulating.
                # Critical for .text: CoW pages persist across Phoenix restarts.
                if wrote and orig != flipped:
                    try:
                        GdbMemWriter(host=GDB_HOST, port=1234).write_byte(spec.addr, orig)
                    except Exception:
                        pass

                _colour = {"CRASH": "\033[91m", "DETECTED": "\033[93m",
                           "MASKED": "\033[92m"}.get(outcome, "")
                print(f"  Outcome: {_colour}{outcome}\033[0m")
                if verdict["evidence"]:
                    print(f"  Evidence: {verdict['evidence']}")
                if verdict["last_events"]:
                    print(f"  Last FS events ({len(verdict['last_events'])}):")
                    for ev in verdict["last_events"]:
                        print(f"    {ev}")
                else:
                    print("  Last FS events: (none FS may be silent)")

                record = {**plugin_resp, "addr": f"0x{spec.addr:08x}",
                          "bit": spec.bit, "outcome": outcome,
                          "evidence": verdict["evidence"]}
                with RESULTS.open("a") as rf:
                    rf.write(json.dumps(record) + "\n")

                if run_id:
                    db.record(
                        run_id=run_id, addr=spec.addr, bit=spec.bit,
                        original=orig, flipped=flipped,
                        write_ok=plugin_resp.get("success", False),
                        outcome=outcome, evidence=verdict["evidence"],
                        insn_count=plugin_resp.get("insn_count"), elf_path=elf,
                    )

                if outcome == "CRASH" and args.redundant and PTY_LOG_B:
                    elapsed = wait_for_cpu_b_takeover(PTY_LOG_B, timeout=60.0)
                    if elapsed is not None:
                        print(f"  \033[92mCPU_B took over in {elapsed:.1f}s\033[0m", flush=True)
                        records = RESULTS.read_text().strip().splitlines()
                        if records:
                            last = json.loads(records[-1])
                            last["cpu_b_takeover_s"] = round(elapsed, 2)
                            last["outcome"] = "CRASH_RECOVERED"
                            records[-1] = json.dumps(last)
                            RESULTS.write_text("\n".join(records) + "\n")
                    else:
                        print("  \033[91mWARNING: CPU_B did not take over!\033[0m", flush=True)
                else:
                    print("  Restarting CHESS for clean state…", flush=True)
                    restarted = restart_chess(PTY_LOG, timeout=120.0)
                    if restarted:
                        print("  FS back online settling 3s…", flush=True)
                        time.sleep(3.0)
                        oracle.drain()
                    else:
                        print("  WARNING: FS did not restart within 120s.", flush=True)
    finally:
        oracle.stop()

    print(f"\nResults appended to {RESULTS}")

    if run_id:
        db.print_run_summary(run_id)
        items = db.compare(run_id)
        db.print_review_queue(items)
        db.close()
