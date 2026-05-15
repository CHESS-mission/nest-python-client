"""Phase: Pairwise state-machine invariant oracle.

Reads EventAction.m_state and OBCSensorsManager.m_state via the TCG plugin
(virtual-address reads, no GDB) and classifies each injection as:

  CORRUPTED    — injected state value is outside the declared enum range.
                 This pair is unconditionally Inconsistent regardless of
                 what the other component's state is.
  INCONSISTENT — both states are individually valid, but the pair violates
                 the pairwise compatibility table.
  VALID_TRANS  — both states valid and compatible; state changed silently.
  MASKED       — state bit pattern unchanged after injection.

The oracle never touches the FS source; it reads memory locations via the
TCG plugin at injection time (correct virtual addresses).
"""

from __future__ import annotations

import sys
import struct
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


# ── EventAction state enum ─────────────────────────────────────────────────
# Enum class State : FwEnumStoreType (alphabetical declaration order):
#   0 __FPRIME_AC_UNINITIALIZED  — hits default: FW_ASSERT in sendSignal_*
#   1 CHARGE
#   2 COM
#   3 DOWNLINK
#   4 LEOP
#   5 MEASURE
#   6 SAFE_SAFE_CHARGE
#   7 SAFE_SAFE_COM
#   8 SAFE_SAFE_DETUMBLE
EA_VALID = set(range(1, 9))          # 0 also triggers FW_ASSERT → excluded
EA_NAMES = {
    0: "UNINITIALIZED", 1: "CHARGE", 2: "COM", 3: "DOWNLINK",
    4: "LEOP", 5: "MEASURE", 6: "SAFE_SAFE_CHARGE",
    7: "SAFE_SAFE_COM", 8: "SAFE_SAFE_DETUMBLE",
}

# Structural byte offset of EventAction.m_state inside the BSS object:
#   m_stateMachine_eventActionSM  : +2944  (DWARF DW_AT_data_member_location)
#   m_state inside SM base class  : +8     (vtbl=+0, m_id=+4, m_state=+8)
EA_M_STATE_OFFSET = 2944 + 8  # = 2952

# ── OBCSensorsManager state enum ──────────────────────────────────────────
# Enum class State : FwEnumStoreType (alphabetical declaration order):
#   0 __FPRIME_AC_UNINITIALIZED
#   1 CONFIG
#   2 HIGHPOLLING
#   3 MANUALOVERRIDE
#   4 NOMINAL
#   5 OFF
OBC_VALID = set(range(1, 6))
OBC_NAMES = {
    0: "UNINITIALIZED", 1: "CONFIG", 2: "HIGHPOLLING",
    3: "MANUALOVERRIDE", 4: "NOMINAL", 5: "OFF",
}

# Structural byte offset of OBCSensorsManager.m_state inside the BSS object:
#   m_stateMachine_obcSensorsManagerSM : +3368  (DWARF)
#   m_state inside SM base class       : +8
OBC_M_STATE_OFFSET = 3368 + 8  # = 3376

# ── Pairwise compatibility table ───────────────────────────────────────────
# (obc_state_value, ea_state_value) → True = Compatible, False = Incompatible
# Pairs absent from the table are treated as Unknown (not flagged).
# Source: design document pairwise matrix.
_COMPAT: dict[tuple[int, int], bool] = {
    # OFF × EventAction states
    (5, 4): True,   # OFF × LEOP
    (5, 2): False,  # OFF × COM
    (5, 1): False,  # OFF × CHARGE
    (5, 5): False,  # OFF × MEASURE
    (5, 6): True,   # OFF × SAFE_SAFE_CHARGE
    (5, 7): True,   # OFF × SAFE_SAFE_COM
    (5, 8): True,   # OFF × SAFE_SAFE_DETUMBLE
    # HIGHPOLLING × EventAction states
    (2, 4): False,  # HIGHPOLLING × LEOP
    (2, 6): False,  # HIGHPOLLING × SAFE_SAFE_CHARGE
}


def _pairwise(obc: int, ea: int) -> str:
    """Classify a (obc_state, ea_state) pair using the compatibility table."""
    if ea not in EA_VALID or obc not in OBC_VALID:
        return "CORRUPTED"
    verdict = _COMPAT.get((obc, ea))
    if verdict is False:
        return "INCONSISTENT"
    if verdict is True:
        return "COMPATIBLE"
    return "UNKNOWN"


def _read_state_byte(fi: FaultInjectorClient, addr: int, bit: int,
                     delay: int) -> tuple[int, int]:
    """
    Schedule one injection and return (original_byte, flipped_byte).
    Uses the TCG plugin which reads virtual addresses correctly.
    """
    trigger = fi.inject_mem(addr=addr, bit=bit, delay=delay)
    r = fi.wait_for_result(timeout=max(30.0, delay / 300_000 + 10.0),
                           trigger_insn=trigger)
    if r is None:
        return 0, 0
    return int(r.get("original", 0)), int(r.get("flipped", 0))


def run_state_machine(args) -> None:
    """
    Pairwise state-machine invariant oracle.

    Probes OBCSensorsManager.m_state once (to learn the current OBC mode),
    then injects into all 32 bits of EventAction.m_state.  After each
    injection the oracle classifies the (OBC, EA_post) pair:

      CORRUPTED    EA state outside enum range — Inconsistent with ANY OBC state
      INCONSISTENT both states valid but pair violates the compatibility table
      VALID_TRANS  pair compatible; EA state changed (latent silent mode change)
      MASKED       EA state unchanged after bit flip
    """
    delay  = getattr(args, "delay", 1_000_000)
    window = max(getattr(args, "window", 5.0), 10.0)

    print_banner("Pairwise State-Machine Invariant Oracle")

    if not ELF_PATH.exists():
        sys.exit(f"ERROR: ELF not found: {ELF_PATH}")

    syms = analyze(ELF_PATH)
    ea_sym  = next((s for s in syms if "eventAction"      in s.name and s.section == ".bss"), None)
    obc_sym = next((s for s in syms if "obcSensorsManager" in s.name and s.section == ".bss"), None)

    if ea_sym is None:
        sys.exit("ERROR: CHESS::eventAction not found in ELF BSS.")
    if obc_sym is None:
        sys.exit("ERROR: CHESS::obcSensorsManager not found in ELF BSS.")

    ea_m_state_addr  = ea_sym.address  + EA_M_STATE_OFFSET
    obc_m_state_addr = obc_sym.address + OBC_M_STATE_OFFSET

    print(f"  eventAction        @ 0x{ea_sym.address:08x}  "
          f"m_state @ 0x{ea_m_state_addr:08x}  (offset +{EA_M_STATE_OFFSET})")
    print(f"  obcSensorsManager  @ 0x{obc_sym.address:08x}  "
          f"m_state @ 0x{obc_m_state_addr:08x}  (offset +{OBC_M_STATE_OFFSET})")
    print()

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
    )

    # ── Step 1: probe OBC m_state (read all 4 bytes via 4 small injections) ──
    print("Probing OBCSensorsManager.m_state …")
    obc_observed = bytearray(4)
    with FaultInjectorClient(SOCK_PATH) as fi:
        for byte_off in range(4):
            orig, _ = _read_state_byte(
                fi, obc_m_state_addr + byte_off, bit=0, delay=delay)
            # Restore bit 0 immediately so the OBC state isn't perturbed
            orig_b0, flip_b0 = _read_state_byte(
                fi, obc_m_state_addr + byte_off, bit=0, delay=delay)
            # Two consecutive bit-0 flips cancel → state restored
            obc_observed[byte_off] = orig  # first read = original value

    obc_state = struct.unpack_from("<I", bytes(obc_observed))[0]
    obc_name  = OBC_NAMES.get(obc_state, f"CORRUPTED({obc_state})")
    print(f"  OBC m_state = 0x{obc_state:08x} = {obc_name}")
    if obc_state not in OBC_VALID:
        print(f"  WARNING: OBC state {obc_state} is already CORRUPTED pre-injection!")
    print()

    # ── Step 2: inject into all 32 bits of EA m_state ─────────────────────
    print("Injecting into EventAction.m_state (4 bytes × 8 bits = 32 targets) …")
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

    campaign = SEUCampaign(cfg)
    run_id = campaign.start_db_run(
        topology="state_machine",
        notes=f"pairwise EA×OBC delay={delay} obc_state={obc_name}",
    )
    campaign.run_targets(specs)

    # ── Step 3: pairwise oracle — override outcome for each result ─────────
    results = campaign._results
    ea_observed = bytearray(4)
    for r in results:
        byte_off = r.spec.byte_offset - EA_M_STATE_OFFSET
        if 0 <= byte_off < 4:
            ea_observed[byte_off] = r.original

    ea_pre = struct.unpack_from("<I", bytes(ea_observed))[0]
    print()
    print("=" * 72)
    print("Pairwise State-Machine Invariant Oracle  —  results")
    print("=" * 72)
    print(f"  Pre-injection  OBC = {obc_name}({obc_state})"
          f"  EA = {EA_NAMES.get(ea_pre, f'CORRUPTED({ea_pre})')}({ea_pre})")
    print(f"  Pre-injection pair verdict: {_pairwise(obc_state, ea_pre)}")
    print()
    print(f"  {'BYTE':>4}  {'BIT':>3}  {'EA_POST':>22}  {'PAIR_VERDICT':>13}  ORACLE_OUT")
    print(f"  {'-'*4}  {'-'*3}  {'-'*22}  {'-'*13}  {'-'*13}")

    counts: dict[str, int] = {}
    by_byte: dict[int, list] = {}
    for r in results:
        b = r.spec.byte_offset - EA_M_STATE_OFFSET
        by_byte.setdefault(b, []).append(r)

    for byte_off in range(4):
        for r in sorted(by_byte.get(byte_off, []), key=lambda x: x.spec.bit):
            new_bytes = bytearray(ea_observed)
            new_bytes[byte_off] = r.flipped
            ea_post = struct.unpack_from("<I", bytes(new_bytes))[0]

            ea_post_name = EA_NAMES.get(ea_post, f"CORRUPTED({ea_post})")
            verdict = _pairwise(obc_state, ea_post)

            if ea_post == ea_pre:
                oracle_out = "MASKED"
            elif verdict == "CORRUPTED":
                oracle_out = "CORRUPTED"
            elif verdict == "INCONSISTENT":
                oracle_out = "INCONSISTENT"
            else:
                oracle_out = "VALID_TRANS"

            r.outcome   = oracle_out   # override PTY-oracle outcome
            r.evidence  = (f"OBC={obc_name} EA_pre={EA_NAMES.get(ea_pre,'?')} "
                           f"EA_post={ea_post_name} pair={verdict}")

            counts[oracle_out] = counts.get(oracle_out, 0) + 1
            print(f"  {byte_off:>4}  {r.spec.bit:>3}  "
                  f"{ea_post_name:>22}  {verdict:>13}  {oracle_out}")

    # ── Step 4: summary ────────────────────────────────────────────────────
    total = sum(counts.values())
    print()
    print(f"  {'OUTCOME':<15}  {'N':>5}  {'%':>5}  MEANING")
    print(f"  {'-'*15}  {'-'*5}  {'-'*5}  {'-'*45}")
    rows = [
        ("CORRUPTED",    "EA state outside valid enum — Inconsistent with any OBC state"),
        ("INCONSISTENT", "Valid pair but violates pairwise compatibility table"),
        ("VALID_TRANS",  "Compatible pair; EA mode changed silently"),
        ("MASKED",       "EA state bit pattern unchanged"),
    ]
    for outcome, meaning in rows:
        n = counts.get(outcome, 0)
        pct = 100 * n / total if total else 0
        print(f"  {outcome:<15}  {n:>5}  {pct:>4.0f}%  {meaning}")
    print()
    print("  CORRUPTED and INCONSISTENT are both 'Inconsistent' in the pairwise table.")
    print("  They appear MASKED to the health monitor — that is the latent fault.")

    if run_id:
        print(f"\n  DB run_id: {run_id[:8]}")
