"""Phase: Pairwise state-machine invariant - EventAction x OBCSensorsManager.

This file needs to be updated when we add more subsystems with state machines that interact with EventAction."""

from __future__ import annotations

import struct
import sys
import time
from pathlib import Path

from nest_client.seu.injector import (
    CampaignConfig, SEUCampaign, InjectionSpec, FaultInjectorClient,
)
from nest_client.seu.elf_analyzer import analyze

from ..config import (
    ELF_PATH, SOCK_PATH, RESULTS, SEU_DB,
    _docker_mode, PTY_LOG, GDB_HOST, CONSOLE_LOG,
)
from ..helpers import print_banner
from ..pairwise import (
    PairwiseHook,
    EA_M_STATE_OFFSET, OBC_M_STATE_OFFSET,
    EA_NAMES, OBC_NAMES, EA_VALID, OBC_VALID, check_pair,
)


def _probe_obc_state(sock_path: Path, obc_m_state_addr: int, delay: int) -> int:
    """
    Read OBCSensorsManager.m_state via two consecutive bit-0 injections
    (double flip cancels itself) and return the current 4-byte state value.

    The plugin reads the byte BEFORE flipping, so the first probe's `original`
    gives us the true runtime byte.  The second probe restores bit 0.
    Uses virtual-address access through the TCG plugin - no GDB needed.
    """
    observed = bytearray(4)
    with FaultInjectorClient(sock_path) as fi:
        for byte_off in range(4):
            addr = obc_m_state_addr + byte_off
            # First probe: get original byte (and flip bit 0)
            trig = fi.inject_mem(addr=addr, bit=0, delay=delay)
            r = fi.wait_for_result(timeout=max(30.0, delay / 300_000 + 10.0),
                                   trigger_insn=trig)
            orig = int(r.get("original", 0)) if r else 0
            observed[byte_off] = orig
            # Second probe: restore bit 0 (flip it back)
            trig2 = fi.inject_mem(addr=addr, bit=0, delay=delay)
            fi.wait_for_result(timeout=max(30.0, delay / 300_000 + 10.0),
                               trigger_insn=trig2)
    return struct.unpack_from("<I", bytes(observed))[0]


def run_state_machine(args) -> None:
    """
    Pairwise state-machine invariant oracle.

    Classification priority (enforced by CampaignConfig.classify_hook):
      1. DETECTED     - FPrime health system observed the fault (sacred).
      2. INCONSISTENT - pairwise table violation; campaign stops immediately.
      3. CORRUPTED    - EA m_state outside valid enum; campaign stops immediately.
      4. CRASH        - process died (pairwise OK or not a state field).
      5. MASKED       - no observable effect.

    Stops on the first INCONSISTENT or CORRUPTED injection and fails with
    exit(1) so this phase can be used as a pre-flight CI gate.
    """
    delay  = getattr(args, "delay", 1_000_000)
    window = max(getattr(args, "window", 5.0), 10.0)

    print_banner("Pairwise State-Machine Invariant  (EA x OBC, stops on INCONSISTENT)")

    if not ELF_PATH.exists():
        sys.exit(f"ERROR: ELF not found: {ELF_PATH}")

    syms = analyze(ELF_PATH)
    ea_sym  = next((s for s in syms if "eventAction"       in s.name and s.section == ".bss"), None)
    obc_sym = next((s for s in syms if "obcSensorsManager" in s.name and s.section == ".bss"), None)

    if ea_sym is None:
        sys.exit("ERROR: CHESS::eventAction not found in ELF BSS.")
    if obc_sym is None:
        sys.exit("ERROR: CHESS::obcSensorsManager not found in ELF BSS.")

    ea_m_state_addr  = ea_sym.address  + EA_M_STATE_OFFSET
    obc_m_state_addr = obc_sym.address + OBC_M_STATE_OFFSET

    print(f"  eventAction        @ 0x{ea_sym.address:08x}  "
          f"m_state @ 0x{ea_m_state_addr:08x}")
    print(f"  obcSensorsManager  @ 0x{obc_sym.address:08x}  "
          f"m_state @ 0x{obc_m_state_addr:08x}")
    print()

    # Step 1: probe OBC m_state before touching EA
    print("Probing OBCSensorsManager.m_state ...")
    obc_state = _probe_obc_state(SOCK_PATH, obc_m_state_addr, delay)
    obc_name  = OBC_NAMES.get(obc_state, f"CORRUPTED({obc_state})")
    print(f"  OBC m_state = 0x{obc_state:08x} = {obc_name}")
    if obc_state not in OBC_VALID:
        print(f"  WARNING: OBC state {obc_state} is already CORRUPTED before any injection!")
    print()

    # Step 2: build the pairwise hook
    hook = PairwiseHook(
        ea_base_addr  = ea_sym.address,
        obc_base_addr = obc_sym.address,
        obc_state     = obc_state,
        stop_on_first = True,   # cut campaign immediately on first violation
    )

    # Step 3: run EA m_state injections (4 bytes x 8 bits = 32 targets)
    specs = [
        InjectionSpec(
            addr        = ea_m_state_addr + byte_off,
            bit         = bit,
            delay       = delay,
            symbol      = ea_sym.name,
            byte_offset = EA_M_STATE_OFFSET + byte_off,
            field_name  = f"m_state[byte{byte_off}]",
        )
        for byte_off in range(4)
        for bit in range(8)
    ]

    _oracle_log = CONSOLE_LOG if CONSOLE_LOG is not None else PTY_LOG

    cfg = CampaignConfig(
        socket_path             = SOCK_PATH,
        elf_path                = ELF_PATH,
        pty_log_path            = _oracle_log,
        delay_insn              = delay,
        observation_window_s    = window,
        candidates_only         = False,
        results_path            = RESULTS,
        db_path                 = SEU_DB,
        use_insn_count_liveness = False,
        gdb_host                = GDB_HOST if _docker_mode else None,
        gdb_port                = 1234,
        classify_hook           = hook,
    )

    campaign = SEUCampaign(cfg)
    run_id = campaign.start_db_run(
        topology="state_machine",
        notes=f"pairwise EAxOBC delay={delay} obc={obc_name}",
    )
    campaign.run_targets(specs)

    # Step 4: summary
    results = campaign._results
    counts: dict[str, int] = {}
    for r in results:
        counts[r.outcome] = counts.get(r.outcome, 0) + 1

    print()
    print("=" * 70)
    print("Pairwise Oracle  -  summary")
    print("=" * 70)
    total = sum(counts.values())
    rows = [
        ("CORRUPTED",    "EA state outside valid enum  [INCONSISTENT with any OBC]"),
        ("INCONSISTENT", "Valid pair but forbidden by design table"),
        ("VALID_TRANS",  "Compatible pair; EA mode changed silently"),
        ("MASKED",       "Bit flip left state unchanged"),
        ("CRASH",        "Process died (FW_ASSERT or kernel panic)"),
        ("DETECTED",     "FPrime logged WARNING/FATAL (health monitoring fired)"),
    ]
    for outcome, meaning in rows:
        n = counts.get(outcome, 0)
        if n:
            print(f"  {outcome:<13}  {n:>3}/{total}  {meaning}")

    if run_id:
        print(f"\n  DB run_id: {run_id[:8]}")

    # Step 5: fail if any pairwise violation found
    hook.fail_if_inconsistent(label="State-machine invariant")
