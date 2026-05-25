"""Pairwise state-machine invariant oracle hook.

Provides a classify_hook for CampaignConfig that runs after the PTY oracle.
Priority contract (enforced by injector.py):
  1. DETECTED  - hook never overrides; FPrime observed the fault itself.
  2. INCONSISTENT / CORRUPTED  - hook fires; campaign can be cut immediately.
  3. CRASH / MASKED  - hook passes through when pairwise is OK.

Usage
-----
    hook = PairwiseHook(ea_sym, obc_sym, obc_state_cache, stop_on_first=True)
    cfg  = CampaignConfig(..., classify_hook=hook)
    campaign.run_targets(specs)
    hook.fail_if_inconsistent()   # sys.exit(1) when called from CI
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nest_client.seu.injector import InjectionResult


# EventAction state enum
# Alphabetical declaration order in the generated Ac.hpp:
#   0 __FPRIME_AC_UNINITIALIZED  -> default branch -> FW_ASSERT
#   1 CHARGE  2 COM  3 DOWNLINK  4 LEOP  5 MEASURE
#   6 SAFE_SAFE_CHARGE  7 SAFE_SAFE_COM  8 SAFE_SAFE_DETUMBLE
EA_VALID   = set(range(1, 9))
EA_NAMES   = {
    0: "UNINITIALIZED", 1: "CHARGE",   2: "COM",      3: "DOWNLINK",
    4: "LEOP",          5: "MEASURE",  6: "SAFE_SAFE_CHARGE",
    7: "SAFE_SAFE_COM", 8: "SAFE_SAFE_DETUMBLE",
}
# Structural byte offsets within eventAction BSS object (DWARF verified):
#   m_stateMachine_eventActionSM : +2944
#   m_state inside SM base       : +8  (vtbl=0, m_id=4, m_state=8)
EA_M_STATE_OFFSET = 2944 + 8  # = 2952

# OBCSensorsManager state enum
# Alphabetical declaration order:
#   0 __FPRIME_AC_UNINITIALIZED
#   1 CONFIG  2 HIGHPOLLING  3 MANUALOVERRIDE  4 NOMINAL  5 OFF
OBC_VALID  = set(range(1, 6))
OBC_NAMES  = {
    0: "UNINITIALIZED", 1: "CONFIG",  2: "HIGHPOLLING",
    3: "MANUALOVERRIDE", 4: "NOMINAL", 5: "OFF",
}
# Structural byte offsets within obcSensorsManager BSS object (DWARF verified):
#   m_stateMachine_obcSensorsManagerSM : +3368
#   m_state inside SM base             : +8
OBC_M_STATE_OFFSET = 3368 + 8  # = 3376

# Pairwise compatibility table
# (obc_state_int, ea_state_int) -> True = Compatible, False = Incompatible
# Pairs absent from the table are not checked (Unknown).
_COMPAT: dict[tuple[int, int], bool] = {
    # OFF x EventAction
    (5, 4): True,   # OFF x LEOP
    (5, 2): False,  # OFF x COM
    (5, 1): False,  # OFF x CHARGE
    (5, 5): False,  # OFF x MEASURE
    (5, 6): True,   # OFF x SAFE_SAFE_CHARGE
    (5, 7): True,   # OFF x SAFE_SAFE_COM
    (5, 8): True,   # OFF x SAFE_SAFE_DETUMBLE
    # HIGHPOLLING x EventAction
    (2, 4): False,  # HIGHPOLLING x LEOP
    (2, 6): False,  # HIGHPOLLING x SAFE_SAFE_CHARGE
}


def check_pair(obc: int, ea: int) -> str:
    """
    Classify a (obc_state, ea_state) pair.

    Returns one of:
      "CORRUPTED"    - at least one state is outside its valid enum range.
                       Unconditionally Inconsistent with any companion state.
      "INCONSISTENT" - both states valid, pair forbidden by the design table.
      "COMPATIBLE"   - pair is explicitly allowed.
      "UNKNOWN"      - pair not covered by the table (not flagged).
    """
    if ea not in EA_VALID or obc not in OBC_VALID:
        return "CORRUPTED"
    verdict = _COMPAT.get((obc, ea))
    if verdict is False:
        return "INCONSISTENT"
    if verdict is True:
        return "COMPATIBLE"
    return "UNKNOWN"


class PairwiseHook:
    """
    classify_hook implementation for CampaignConfig.

    Call as a callable: ``hook(result) -> str | None``.

    The hook intercepts injections that target EA or OBC m_state fields,
    reconstructs the 4-byte post-injection state, runs the pairwise check,
    and overrides the outcome:

      CORRUPTED    -> state out of enum range - stop if stop_on_first=True
      INCONSISTENT -> valid pair but forbidden - stop if stop_on_first=True
      None         -> target not a state field, or pairwise OK

    After the campaign, call fail_if_inconsistent() to exit(1) in CI mode.
    """

    def __init__(self,
                 ea_base_addr:  int,
                 obc_base_addr: int,
                 obc_state:     int,
                 stop_on_first: bool = False):
        self.ea_m_state_addr  = ea_base_addr  + EA_M_STATE_OFFSET
        self.obc_m_state_addr = obc_base_addr + OBC_M_STATE_OFFSET
        self.obc_state        = obc_state      # probed before campaign starts
        self.stop_on_first    = stop_on_first

        # Track EA m_state bytes across injections so we can reconstruct the
        # full 4-byte word even when different bytes are targeted in sequence.
        self._ea_observed: bytearray = bytearray(4)
        self.violations: list[dict]  = []      # accumulated INCONSISTENT records

    def _ea_byte_off(self, addr: int) -> int | None:
        """Return byte offset (0-3) if addr is within EA m_state, else None."""
        off = addr - self.ea_m_state_addr
        return off if 0 <= off < 4 else None

    def __call__(self, result: "InjectionResult") -> str | None:
        byte_off = self._ea_byte_off(result.spec.addr)
        if byte_off is None:
            return None  # injection not targeting EA m_state - don't interfere

        # Update our picture of the pre-injection EA state from the plugin read.
        self._ea_observed[byte_off] = result.original

        # Reconstruct the full 4-byte m_state AFTER this bit flip.
        new_bytes = bytearray(self._ea_observed)
        new_bytes[byte_off] = result.flipped
        ea_post = struct.unpack_from("<I", bytes(new_bytes))[0]

        verdict = check_pair(self.obc_state, ea_post)

        obc_name = OBC_NAMES.get(self.obc_state, f"CORRUPTED({self.obc_state})")
        ea_name  = EA_NAMES.get(ea_post, f"CORRUPTED({ea_post})")

        if verdict in ("CORRUPTED", "INCONSISTENT"):
            result.evidence = (
                f"pairwise {verdict}: OBC={obc_name}({self.obc_state}) "
                f"x EA_post={ea_name}({ea_post})"
            )
            self.violations.append({
                "addr":    f"0x{result.spec.addr:08x}",
                "bit":     result.spec.bit,
                "obc":     obc_name,
                "ea_post": ea_name,
                "verdict": verdict,
            })
            return "STOP" if self.stop_on_first else verdict

        return None

    def fail_if_inconsistent(self, label: str = "CI") -> None:
        """
        Print a summary of violations and sys.exit(1) if any were found.
        Call this at the end of run_ci() or run_automated_sweep() to enforce
        the pairwise invariant as a hard CI gate.
        """
        if not self.violations:
            return
        n = len(self.violations)
        print(f"\n  *** {label} FAILED - {n} pairwise invariant violation(s) ***")
        for v in self.violations:
            print(f"    {v['addr']} bit={v['bit']}  "
                  f"OBC={v['obc']} x EA={v['ea_post']}  -> {v['verdict']}")
        print(f"\n  INCONSISTENT / CORRUPTED states indicate a mission-critical "
              f"latent fault:\n  the subsystem appears healthy but will produce "
              f"incorrect behavior on the next valid command.")
        sys.exit(1)
