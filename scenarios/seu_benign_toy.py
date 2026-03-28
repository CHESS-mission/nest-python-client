#!/usr/bin/env python3
"""
seu_benign_toy.py — Minimal fault injection example, benign targets only.

Targets four fields in CHESS::obcSensorsManager that are expected to produce
MASKED outcomes — the simplest possible end-to-end demonstration of the
injection pipeline without crashing the flight software.

Why each target is expected BENIGN (MASKED)
-------------------------------------------
  magConsecutiveFailures (U8, bit 0)
    Counter incremented on each failed magnetometer read.
    Recovery logic triggers only after N consecutive failures (N ≥ 3).
    Flipping bit 0: 0 → 1 puts the counter at 1, below any threshold.
    The next successful mag read resets it to 0.  No observable effect.

  imuMeasured (bool, bit 0)
    Per-cycle flag: "has IMU been sampled this cycle?"
    Flip to 0 (not measured): triggers an extra poll next iteration. Silent.
    Flip to 1 (already measured): skips one poll. One missing sample in a
    stream of continuous readings — well within sensor fusion tolerance.

  magMeasured (bool, bit 0)
    Same as imuMeasured but for the magnetometer. Same reasoning applies.

Address resolution
------------------
  The base address of obcSensorsManager is resolved at runtime from the ELF
  symbol table via elf_analyzer.analyze().  Field offsets are derived from
  DWARF debug info when available; otherwise the documented fallback offsets
  (valid for CHESS_Pathfinder0FS built at the reference commit) are used.

  Set ELF_PATH env var to override the default binary location.

Run
---
  cd nest-python-client
  python3 scenarios/seu_benign_toy.py

  # With a custom ELF or PTY log path:
  ELF_PATH=/path/to/CHESS_Pathfinder0FS \\
  NEST_PTY_LOG=/tmp/my_serial.log \\
  python3 scenarios/seu_benign_toy.py
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

from nest_client.seu.injector import FaultInjectorClient, InjectionSpec, PtyOracle
from nest_client.seu.elf_analyzer import analyze, expand_symbol_fields
from nest_client.client import NestClient
from nest_client.types import EnvVarType

# ── Configuration ─────────────────────────────────────────────────────────────

_SP = Path(__file__).resolve().parent.parent.parent  # repo root

SOCK_PATH = Path(os.environ.get("FAULT_INJECT_SOCK", "/tmp/fi.sock"))
PTY_LOG   = Path(os.environ.get("NEST_PTY_LOG", "/tmp/qemu-serial-pty"))
RESULTS   = Path(os.environ.get("SEU_RESULTS", "/tmp/seu_benign_toy.jsonl"))
ELF_PATH  = Path(os.environ.get(
    "ELF_PATH",
    str(_SP / "CHESS-FS" / "build-fprime-automatic-arm-hf-linux"
              / "bin" / "arm-hf-linux" / "CHESS_Pathfinder0FS"),
))
TOPOLOGY  = Path(os.environ.get(
    "SEU_TOPOLOGY",
    str(_SP / "nest" / "examples" / "topology_seu.yaml"),
))

INJECTION_DELAY      = 10_000_000
OBSERVATION_WINDOW_S = 8.0

# ── Fallback field offsets ─────────────────────────────────────────────────────
# Byte offsets from the start of obcSensorsManager, measured from the reference
# build (CHESS_Pathfinder0FS @ bss base 0x0012efc0).  Used only when DWARF info
# is not available in the target binary.
#
#   field                   offset  type  rationale
#   ─────────────────────────────────────────────────
#   imuMeasured             3156    bool  per-cycle poll flag
#   magMeasured             3157    bool  per-cycle poll flag
#   magConsecutiveFailures  3158    U8    failure counter
_FALLBACK_OFFSETS: dict[str, tuple[int, str, str]] = {
    "imuMeasured":            (3156, "bool", "bool per-cycle flag — one skipped/extra poll, invisible to health"),
    "magMeasured":            (3157, "bool", "bool per-cycle flag — same as imuMeasured"),
    "magConsecutiveFailures": (3158, "U8",   "U8 counter — value 0→1 stays below recovery threshold"),
}

# ── Target resolution ──────────────────────────────────────────────────────────

_SYM_RE = re.compile(r"obcSensorsManager", re.IGNORECASE)


def _find_symbol_base(elf_path: Path) -> int:
    """Return the virtual address of obcSensorsManager from the ELF symbol table."""
    symbols = analyze(elf_path, filter_re=_SYM_RE)
    for sym in symbols:
        if _SYM_RE.search(sym.demangled) and sym.sym_type in {"OBJECT", "COMMON", "TLS"}:
            return sym.address
    raise RuntimeError(
        f"Symbol 'obcSensorsManager' not found in {elf_path}.\n"
        "  Is the binary stripped?  Was it linked with that symbol name?"
    )


def _field_offsets_from_dwarf(elf_path: Path) -> dict[str, int] | None:
    """
    Try to extract {field_name: byte_offset} for obcSensorsManager from DWARF.
    Returns None if DWARF is absent or the symbol's layout cannot be parsed.
    """
    symbols = analyze(elf_path, filter_re=_SYM_RE)
    targets = [s for s in symbols
               if _SYM_RE.search(s.demangled) and s.sym_type in {"OBJECT", "COMMON", "TLS"}]
    if not targets:
        return None

    expansion = expand_symbol_fields(elf_path, targets)
    if not expansion:
        return None

    # Use the first (and typically only) matching symbol
    sym = targets[0]
    fields = expansion.get(sym.name, [])
    if not fields:
        return None

    return {fi.field_name: fi.offset for fi in fields}


def build_targets(elf_path: Path, delay: int) -> list[tuple[str, InjectionSpec, str]]:
    """
    Resolve BENIGN_TARGETS from the ELF binary.

    1. Look up obcSensorsManager base address in the symbol table.
    2. Try to derive field offsets from DWARF; fall back to _FALLBACK_OFFSETS.
    3. Return list of (field_name, InjectionSpec, rationale) tuples.
    """
    base = _find_symbol_base(elf_path)
    print(f"  obcSensorsManager base : 0x{base:010x}", file=sys.stderr)

    dwarf_offsets = _field_offsets_from_dwarf(elf_path)
    if dwarf_offsets is not None:
        print(f"  Field offsets         : from DWARF ({len(dwarf_offsets)} fields parsed)",
              file=sys.stderr)
    else:
        print("  Field offsets         : using fallback (no DWARF in binary)",
              file=sys.stderr)

    targets: list[tuple[str, InjectionSpec, str]] = []
    for field_name, (fallback_off, _, rationale) in _FALLBACK_OFFSETS.items():
        if dwarf_offsets is not None and field_name in dwarf_offsets:
            offset = dwarf_offsets[field_name]
            source = "DWARF"
        else:
            offset = fallback_off
            source = "fallback"
        addr = base + offset
        print(f"    {field_name:<28} +{offset}  0x{addr:010x}  [{source}]",
              file=sys.stderr)
        targets.append((
            field_name,
            InjectionSpec(addr=addr, bit=0, delay=delay),
            rationale,
        ))
    return targets

# ── Helpers ───────────────────────────────────────────────────────────────────

def start_simulation(topology_path: Path, nest_url: str = "ws://localhost:3000/ws") -> None:
    """Upload topology_seu.yaml and start QEMU, then wait until running."""
    print(f"Starting simulation (topology: {topology_path.name}) …")
    topology_yaml = topology_path.read_text()
    with NestClient(url=nest_url) as client:
        client.upload_topology(topology_yaml)
        client.start()
        client.wait_for_status("running")
    print("  Simulation running.  ✓")


def set_nominal_environment(nest_url: str = "ws://localhost:3000/ws") -> None:
    """
    Push nominal sensor environment variables to NEST before starting injections.

    Values mirror sensors_fuzz.py env_ramp() steady-state targets:
      temp    = 35.0 °C
      accel   = [0.5, 0.5, 9.8]  g
      omega   = [0.1, 0.2, 0.3]  dps
      B_field = non-zero raw counts (passes both raw-register and app-level checks)
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


def wait_for_chess_ready(timeout: float = 120.0) -> bool:
    """Block until FPrime logs a steady-state marker on the PTY."""
    print(f"Waiting for CHESS ready (PTY: {PTY_LOG}) …")
    deadline = time.monotonic() + timeout
    _READY = ["OpCodeRegistered", "Starting HealthImpl",
              "Registered with", "SENSOR_POLL_CYCLE", "rate group"]
    while time.monotonic() < deadline:
        try:
            with PTY_LOG.open("r", errors="replace") as f:
                while time.monotonic() < deadline:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    if any(kw in line for kw in _READY):
                        print(f"  Ready: {line.strip()}")
                        return True
        except (FileNotFoundError, OSError):
            time.sleep(0.5)
    print("  WARNING: timed out — proceeding anyway.")
    return False


def sep(title: str = "") -> None:
    print("\n" + "─" * 68)
    if title:
        print(f"  {title}")
        print("─" * 68)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    sep("SEU Toy Scenario — Benign Targets (obcSensorsManager)")
    print(f"  Plugin socket : {SOCK_PATH}")
    print(f"  PTY log       : {PTY_LOG}")
    print(f"  Results file  : {RESULTS}")
    print(f"  ELF binary    : {ELF_PATH}")
    print(f"  Delay         : {INJECTION_DELAY:,} instructions per injection")
    print(f"  Window        : {OBSERVATION_WINDOW_S}s observation per injection")

    if not os.environ.get("SEU_NO_START"):
        start_simulation(TOPOLOGY)
    set_nominal_environment()

    sep("Resolving target addresses from ELF")
    try:
        benign_targets = build_targets(ELF_PATH, INJECTION_DELAY)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"  {len(benign_targets)} targets resolved.")

    wait_for_chess_ready()

    oracle = PtyOracle(PTY_LOG)
    oracle.start()

    results: list[dict] = []

    try:
        with FaultInjectorClient(SOCK_PATH) as fi:
            baseline_count = fi.get_count()
            print(f"\nPlugin connected. Instruction count at start: {baseline_count:,}")

            for i, (field_name, spec, rationale) in enumerate(benign_targets):
                sep(f"[{i+1}/{len(benign_targets)}]  {field_name}")
                print(f"  Address   : 0x{spec.addr:08x}")
                print(f"  Bit       : {spec.bit}")
                print(f"  Why safe  : {rationale}")

                trigger_insn = fi.inject_mem(
                    addr=spec.addr, bit=spec.bit, delay=spec.delay
                )
                print(f"  Scheduled : fires at instruction {trigger_insn:,}")

                t0 = time.monotonic()
                plugin_resp = fi.wait_for_result(
                    timeout=60.0, trigger_insn=trigger_insn
                )
                elapsed = time.monotonic() - t0

                if plugin_resp is None:
                    print("  TIMEOUT: injection did not fire — delay too large?")
                    results.append({
                        "field": field_name, "addr": f"0x{spec.addr:08x}",
                        "bit": spec.bit, "outcome": "NO_INJECT",
                    })
                    continue

                orig    = plugin_resp.get("original", 0)
                flipped = plugin_resp.get("flipped", 0)
                wrote   = plugin_resp.get("success", False)
                print(f"  Fired     : 0x{orig:02x} → 0x{flipped:02x}  "
                      f"({orig:08b} → {flipped:08b})  write_ok={wrote}")

                print(f"  Observing for {OBSERVATION_WINDOW_S}s …")
                verdict = oracle.classify(OBSERVATION_WINDOW_S)
                outcome = verdict["outcome"]

                _colour = {
                    "CRASH":    "\033[91m",
                    "DETECTED": "\033[93m",
                    "MASKED":   "\033[92m",
                }.get(outcome, "")
                _reset = "\033[0m"

                print(f"  Outcome   : {_colour}{outcome}{_reset}", end="")
                if outcome == "MASKED":
                    print("  ✓ (expected)")
                else:
                    print(f"  ← UNEXPECTED (expected MASKED)")

                if verdict["evidence"]:
                    print(f"  Evidence  : {verdict['evidence']}")
                if verdict["last_events"]:
                    print(f"  FS events : {verdict['last_events'][-1]}")

                record = {
                    "field":     field_name,
                    "addr":      f"0x{spec.addr:08x}",
                    "bit":       spec.bit,
                    "original":  f"0x{orig:02x}",
                    "flipped":   f"0x{flipped:02x}",
                    "write_ok":  wrote,
                    "outcome":   outcome,
                    "evidence":  verdict["evidence"],
                    "elapsed_s": round(elapsed, 2),
                }
                results.append(record)
                with RESULTS.open("a") as rf:
                    rf.write(json.dumps(record) + "\n")

                time.sleep(2.0)

    finally:
        oracle.stop()

    sep("Summary")
    from collections import Counter
    counts = Counter(r["outcome"] for r in results)
    total  = len(results)
    for outcome, n in sorted(counts.items()):
        _colour = {
            "MASKED":   "\033[92m",
            "DETECTED": "\033[93m",
            "CRASH":    "\033[91m",
        }.get(outcome, "")
        _reset = "\033[0m"
        pct = 100 * n / total if total else 0
        print(f"  {_colour}{outcome:<12}{_reset}  {n}/{total}  ({pct:.0f}%)")

    masked = counts.get("MASKED", 0)
    if masked == total:
        print("\n  All injections masked — pipeline verified end-to-end.")
    else:
        print(f"\n  {total - masked} unexpected outcome(s) — review evidence above.")

    print(f"\n  Results: {RESULTS}")
    sys.exit(0 if masked == total else 1)


if __name__ == "__main__":
    main()
