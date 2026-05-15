"""Phase: State machine invariant — EventAction m_state SEU sensitivity."""

from __future__ import annotations

import sys
import struct
import time
from pathlib import Path

from nest_client.seu.injector import (
    CampaignConfig, SEUCampaign, InjectionSpec,
)
from nest_client.seu.elf_analyzer import analyze

from ..config import (
    ELF_PATH, SOCK_PATH, RESULTS, SEU_DB,
    _docker_mode, PTY_LOG, GDB_HOST, CONSOLE_LOG,
)
from ..helpers import print_banner


# State enum values from EventAction_EventActionSMStateMachineAc.hpp
# Declarations order: __FPRIME_AC_UNINITIALIZED=0, CHARGE=1, COM=2,
# DOWNLINK=3, LEOP=4, MEASURE=5, SAFE_SAFE_CHARGE=6, SAFE_SAFE_COM=7,
# SAFE_SAFE_DETUMBLE=8
# 0 (__FPRIME_AC_UNINITIALIZED) hits default: FW_ASSERT in sendSignal_*; excluded.
_VALID_STATES = {1, 2, 3, 4, 5, 6, 7, 8}
_STATE_NAMES = {
    0: "UNINITIALIZED",
    1: "CHARGE",
    2: "COM",
    3: "DOWNLINK",
    4: "LEOP",
    5: "MEASURE",
    6: "SAFE_SAFE_CHARGE",
    7: "SAFE_SAFE_COM",
    8: "SAFE_SAFE_DETUMBLE",
}

# Offset of m_state within EventAction object:
#   m_stateMachine_eventActionSM: +2944 (from DWARF)
#   m_state within EventAction_EventActionSMStateMachineBase: +8 (vtbl=0, m_id=4)
_M_STATE_OFFSET = 2944 + 8   # = 2952


def run_state_machine(args) -> None:
    """
    Target the EventAction state machine m_state field directly.

    Injects bit flips into the 4 bytes of m_state and classifies each as:
    - LATENT_CRITICAL : flip produces invalid State enum value (>8); the next
                        sendSignal_*() call would trigger FW_ASSERT -> CRASH.
    - VALID_TRANSITION: flip produces a different but valid State value.
    - MASKED          : flip reproduces the same State value (e.g. flip within
                        upper 3 bytes that are already 0).

    The injection itself reads the original byte via the TCG plugin (virtual
    address), so no GDB memory access is needed.
    """
    delay = getattr(args, "delay", 1_000_000)
    window = max(getattr(args, "window", 5.0), 10.0)

    print_banner("EventAction State Machine Invariant  (m_state SEU sensitivity)")

    if not ELF_PATH.exists():
        sys.exit(f"ERROR: ELF not found: {ELF_PATH}")

    syms = analyze(ELF_PATH)
    ea_sym = next((s for s in syms
                   if "eventAction" in s.name and s.section == ".bss"), None)
    if ea_sym is None:
        sys.exit("ERROR: CHESS::eventAction not found in ELF BSS. "
                 "Was EventAction added to the topology and rebuilt?")

    ea_base = ea_sym.address
    m_state_addr = ea_base + _M_STATE_OFFSET

    print(f"  eventAction  @ 0x{ea_base:08x}  size={ea_sym.size}")
    print(f"  m_state      @ 0x{m_state_addr:08x}  (offset +{_M_STATE_OFFSET})")
    print()

    # 4 bytes × 8 bits = 32 injection targets for the full m_state word
    specs = [
        InjectionSpec(
            addr=m_state_addr + byte_off,
            bit=bit,
            delay=delay,
            symbol="_ZN5CHESS11eventActionE",
            byte_offset=_M_STATE_OFFSET + byte_off,
            field_name=f"m_state[byte{byte_off}]",
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
    )
    campaign = SEUCampaign(cfg)
    run_id = campaign.start_db_run(
        topology="state_machine",
        notes=f"eventAction m_state 32-bit sweep delay={delay}",
    )

    campaign.run_targets(specs)

    # Post-process: classify based on original byte read by TCG plugin + bit flip.
    # The plugin reads the ACTUAL byte at injection time (virtual address, correct).
    # LEOP=4 → bytes [0x04, 0x00, 0x00, 0x00] in little-endian; reconstruct the
    # 4-byte m_state word from whichever byte was injected.
    results = campaign._results

    print()
    print("=" * 70)
    print("State Machine Invariant Analysis")
    print("=" * 70)

    # Group by byte offset within m_state
    by_byte: dict[int, list] = {}
    for r in results:
        byte_off = r.spec.byte_offset - _M_STATE_OFFSET
        by_byte.setdefault(byte_off, []).append(r)

    # Build the observed pre-injection m_state from the original bytes
    observed = bytearray(4)
    for r in results:
        byte_off = r.spec.byte_offset - _M_STATE_OFFSET
        if 0 <= byte_off < 4:
            observed[byte_off] = r.original
    pre_state = struct.unpack_from("<I", bytes(observed))[0]
    pre_name = _STATE_NAMES.get(pre_state, f"UNKNOWN({pre_state})")
    print(f"  Pre-injection m_state: 0x{pre_state:08x} = {pre_name}")
    print()

    latent_critical = 0
    valid_transition = 0
    masked_count = 0

    print(f"  {'BYTE':>4}  {'BIT':>3}  {'ORIG':>4}  {'FLIP':>4}  {'NEW_STATE':>20}  STATUS")
    print(f"  {'-'*4}  {'-'*3}  {'-'*4}  {'-'*4}  {'-'*20}  {'-'*25}")

    for byte_off in range(4):
        for r in sorted(by_byte.get(byte_off, []), key=lambda x: x.spec.bit):
            orig_byte = r.original
            flip_byte = r.flipped
            # Build the 4-byte m_state after this byte flip
            new_bytes = bytearray(observed)
            new_bytes[byte_off] = flip_byte
            new_state = struct.unpack_from("<I", bytes(new_bytes))[0]

            state_name = _STATE_NAMES.get(new_state, f"INVALID({new_state})")
            is_valid = new_state in _VALID_STATES

            if new_state == pre_state:
                status = "MASKED     (state unchanged)"
                masked_count += 1
            elif is_valid:
                status = "VALID_TRANS (silent mode change)"
                valid_transition += 1
            else:
                status = "LATENT_CRIT (FW_ASSERT on signal)"
                latent_critical += 1

            print(f"  {byte_off:>4}  {r.spec.bit:>3}  "
                  f"0x{orig_byte:02x}  0x{flip_byte:02x}  "
                  f"  {state_name:>20}  {status}")

    total = latent_critical + valid_transition + masked_count
    if total == 0:
        print("  (no results — did the campaign run?)")
        return

    print()
    print(f"  Total: {total} injections")
    print(f"    LATENT_CRITICAL   {latent_critical:3d}/{total}  "
          f"({100*latent_critical/total:.0f}%)  — FW_ASSERT on next sendSignal()")
    print(f"    VALID_TRANSITION  {valid_transition:3d}/{total}  "
          f"({100*valid_transition/total:.0f}%)  — mode changed silently, no crash")
    print(f"    MASKED            {masked_count:3d}/{total}  "
          f"({100*masked_count/total:.0f}%)  — m_state bit pattern unchanged")
    print()
    print("  Interpretation:")
    print("    LATENT_CRITICAL looks like MASKED to health monitoring.")
    print("    The fault only triggers when GO_TO_CHARGE_MODE/GO_TO_SAFE_MODE fires.")
    print("    This is the latent corruption scenario: FS appears healthy but is broken.")

    if run_id:
        print(f"\n  DB run_id: {run_id[:8]}")
