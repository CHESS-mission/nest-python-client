"""Layer-5 GOLDEN integrity check - shared between --ci and --ci-debug.

Provides:
  - CriticalParam              dataclass: one safety-critical BSS word to watch
  - build_health_critical_params : snapshots Health watchdog table at boot
  - check_critical_params      : reads all params in one GDB halt, returns drifts

Scope (v1): Health watchdog table only - m_numPingEntries + 13 x {warnCycles,
fatalCycles}.  These are DWARF-verified offsets we already exercise in the
HLTH_PING_* synthetics, so resolution is rock-solid.  Adding more critical
params later (rate-group divisors, sensor state, etc.) is a one-liner per param
once their offsets are known.
"""
from __future__ import annotations

import os
import random
import struct
import time
from dataclasses import dataclass
from pathlib import Path

from nest_client.seu.elf_analyzer import analyze_cached as analyze, SymbolInfo


# Stable ELF (release binary that matches what's actually running in QEMU).
# Set via CHESS_STABLE_ELF_PATH env var.  Without it, fall back to whatever
# ELF the caller passed in - addresses may not match runtime BSS layout.
_STABLE_ELF_PATH: Path | None = (
    Path(os.environ["CHESS_STABLE_ELF_PATH"])
    if os.environ.get("CHESS_STABLE_ELF_PATH") else None
)


# Health PingTracker layout (FPrime-defined, stable while FPrime version is pinned)
PING_ENTRY_ARRAY_OFFSET = 7080    # m_pingTrackerEntries[0] from health base
PING_ENTRY_SIZE         = 296     # bytes per PingTracker entry
PING_WC_OFF             = 0       # warnCycles  U64 (low 32 bits at +0)
PING_FC_OFF             = 8       # fatalCycles U64 (low 32 bits at +8)
PING_CC_OFF             = 280     # cycleCount  U32
PING_KEY_OFF            = 284     # key         U32
PING_ENABLED_OFF        = 288     # enabled     U32 (Fw::Enabled enum)
HEALTH_VTABLE_OFFSET    = 0       # vtable pointer is first 4 bytes of C++ object
HEALTH_NPE_OFFSET       = 14480   # m_numPingEntries U16

# Maximum slots in HealthComponentImpl::m_pingTrackerEntries[].  Derived from
# the layout (array spans the gap between PING_ENTRY_ARRAY_OFFSET and the next
# member m_numPingEntries), so it auto-tracks FPrime's compile-time max.
# We read up to this many slots; only the first `m_numPingEntries` are
# registered as critical params - that count is read live from RAM at boot,
# so adding a Health-monitored component in CHESS topology Just Works as long
# as the count stays <= MAX_HEALTH_SLOTS.
MAX_HEALTH_SLOTS = (HEALTH_NPE_OFFSET - PING_ENTRY_ARRAY_OFFSET) // PING_ENTRY_SIZE


@dataclass(frozen=True)
class CriticalParam:
    name:     str   # human-readable label, used in suspect evidence
    addr:     int   # absolute BSS address
    size:     int   # bytes to read (1, 2, or 4)
    expected: int   # value snapshotted at boot from real RAM
    fmt:      str   # struct format: "<B", "<H", or "<I"


def find_health_entry0_addr(syms: list[SymbolInfo]) -> int | None:
    """Return address of m_pingTrackerEntries[0] in CdhCore::health, or None.

    Prefers the stable ELF (CHESS_STABLE_ELF_PATH) because debug builds shift
    BSS addresses.  Falls back to the passed-in syms if the stable ELF isn't
    set.
    """
    health = None
    if _STABLE_ELF_PATH is not None and _STABLE_ELF_PATH.exists():
        try:
            stable_syms = analyze(_STABLE_ELF_PATH)
            health = next((s for s in stable_syms
                           if "health" in s.demangled.lower()
                           and "CdhCore" in s.demangled
                           and "pingEntries" not in s.demangled
                           and s.section == ".bss"), None)
        except Exception:
            health = None
    if health is None:
        health = next((s for s in syms
                       if "health" in s.demangled.lower()
                       and "CdhCore" in s.demangled
                       and "pingEntries" not in s.demangled
                       and s.section == ".bss"), None)
    if health is None:
        return None
    return health.address + PING_ENTRY_ARRAY_OFFSET

_GOLDEN_BUILD_RETRIES = 120


def _context_poll_sleep() -> None:
    """Let the guest run a jittered interval before the next halt attempt.

    A fixed delay can alias with CHESS's ~1 Hz rate-group schedule, so we keep
    re-sampling the same execution phase and never catch userspace.  Jitter
    breaks that harmonic so successive halts land in different phases.
    """
    time.sleep(0.15 + random.random() * 0.25)


def build_health_critical_params(syms: list[SymbolInfo],
                                  gdb,
                                  max_retries: int = _GOLDEN_BUILD_RETRIES) -> list[CriticalParam]:
    """Resolve + snapshot Health watchdog table from a clean CHESS.

    Auto-sized - the loop registers exactly the components Health is monitoring
    at boot, by reading m_numPingEntries from RAM.  Adding a new Health entry
    in CHESS topology (e.g. registering a 14th subsystem) requires no code
    change here - the next boot picks it up automatically.

    Param count = 2 + 3 x m_numPingEntries:
      - 1 x Health.vtable             (constant pointer into .text)
      - 1 x m_numPingEntries          (U16; loop bound for Health::Run)
      - N x entry[i].warnCycles       (U32; WARN threshold for component i)
      - N x entry[i].fatalCycles      (U32; FATAL threshold for component i)
      - N x entry[i].enabled          (U32; ENABLED/DISABLED flag for component i)

    Single GDB halt reads MAX_HEALTH_SLOTS slots (over-reads by a few words
    when not all FPrime slots are used).  Retries on GDB context misses (CPU
    caught in kernel -> empty reads).  Accepts once m_numPingEntries reads back
    as a plausible non-zero value AND every entry read returns >=4 bytes.
    """
    entry0 = find_health_entry0_addr(syms)
    if entry0 is None:
        print("  WARNING: CdhCore::health not found - Layer-5 disabled", flush=True)
        return []
    h_base    = entry0 - PING_ENTRY_ARRAY_OFFSET
    npe_addr  = h_base + HEALTH_NPE_OFFSET
    vt_addr   = h_base + HEALTH_VTABLE_OFFSET

    # Phase 1: read npe + vtable (2 reads, high success rate)
    # We need m_numPingEntries to know how many PingTracker slots to read in
    # phase 2; reading just 2 small fields here avoids the failure mode where
    # an over-large bulk read has ~1 word that misses CHESS context and kills
    # `all_ok` for the whole batch.
    npe_val = None
    vt_val  = None
    for attempt in range(max_retries):
        data = gdb.read_bulk([(npe_addr, 2), (vt_addr, 4)])
        if (data and len(data) == 2
                and data[0] and len(data[0]) >= 2
                and data[1] and len(data[1]) >= 4):
            npe_candidate = struct.unpack_from("<H", data[0][:2])[0]
            vt_candidate  = struct.unpack_from("<I", data[1][:4])[0]
            # Plausibility: npe must be in FPrime range, vtable must be non-zero
            # (vtable=0 = wrong context — real null vtable would already have
            # crashed CHESS via virtual dispatch before we got here).
            if 1 <= npe_candidate <= MAX_HEALTH_SLOTS and vt_candidate != 0:
                npe_val = npe_candidate
                vt_val  = vt_candidate
                if attempt > 0:
                    print(f"  critical-params phase 1: caught CHESS context on attempt {attempt+1}",
                          flush=True)
                break
        _context_poll_sleep()
    if npe_val is None:
        print(f"  WARNING: critical-params phase 1 (npe/vtable) failed after {max_retries} retries "
              "- Layer-5 disabled", flush=True)
        return []

    # Phase 2: read exactly the npe_val PingTracker slots that Health uses
    entry_reads: list[tuple[int, int]] = []
    for i in range(npe_val):
        e = entry0 + i * PING_ENTRY_SIZE
        entry_reads.append((e + PING_WC_OFF,      4))
        entry_reads.append((e + PING_FC_OFF,      4))
        entry_reads.append((e + PING_ENABLED_OFF, 4))

    entry_data: list[bytes] = []
    for attempt in range(max_retries):
        entry_data = gdb.read_bulk(entry_reads)
        all_ok = (entry_data and len(entry_data) == len(entry_reads)
                  and all(d and len(d) >= 4 for d in entry_data))
        if all_ok:
            if attempt > 0:
                print(f"  critical-params phase 2: caught CHESS context on attempt {attempt+1}",
                      flush=True)
            break
        _context_poll_sleep()
    else:
        print(f"  WARNING: critical-params phase 2 (entries) failed after {max_retries} retries "
              "- Layer-5 disabled", flush=True)
        return []

    # Assemble the param list
    params: list[CriticalParam] = [
        CriticalParam("Health.m_numPingEntries", npe_addr, 2, npe_val, "<H"),
        CriticalParam("Health.vtable",           vt_addr,  4, vt_val,  "<I"),
    ]
    for i in range(npe_val):
        e        = entry0 + i * PING_ENTRY_SIZE
        idx_base = 3 * i
        wc_val   = struct.unpack_from("<I", entry_data[idx_base + 0])[0]
        fc_val   = struct.unpack_from("<I", entry_data[idx_base + 1])[0]
        en_val   = struct.unpack_from("<I", entry_data[idx_base + 2])[0]
        params.append(CriticalParam(f"entry[{i}].warnCycles",
                                    e + PING_WC_OFF, 4, wc_val, "<I"))
        params.append(CriticalParam(f"entry[{i}].fatalCycles",
                                    e + PING_FC_OFF, 4, fc_val, "<I"))
        params.append(CriticalParam(f"entry[{i}].enabled",
                                    e + PING_ENABLED_OFF, 4, en_val, "<I"))
    print(f"  Layer-5 auto-sized: registered {len(params)} params "
          f"(m_numPingEntries={npe_val}, MAX_HEALTH_SLOTS={MAX_HEALTH_SLOTS})",
          flush=True)
    return params


def check_critical_params(params: list[CriticalParam],
                          gdb,
                          max_retries: int = 30) -> list[tuple[str, int, int]]:
    """Read all registered params in one GDB halt; return divergences.

    Retries on GDB context misses.  Two layers of context-miss detection:
      1. read_bulk returns empty bytes - request didn't get a response
      2. read_bulk returns ALL-ZERO bytes - happens when GDB halts in kernel
         context and the user-space BSS isn't currently mapped.  Distinguished
         from a real corruption by a canary: `Health.vtable` is always a
         non-zero text pointer in normal operation; vtable=0 would CRASH, so
         a MASKED outcome can never legitimately have vtable=0.

    Returns [(name, expected, actual), ...] - empty when everything matches.
    """
    if not params:
        return []

    # Find the vtable canary in the registered list (it's added second in the
    # builder, but locate by name to stay robust to ordering changes).
    canary_idx = next((i for i, p in enumerate(params) if p.name == "Health.vtable"), None)

    reads = [(p.addr, p.size) for p in params]
    data: list[bytes] = []
    for attempt in range(max_retries):
        data = gdb.read_bulk(reads)
        all_ok = (data and len(data) == len(reads)
                  and all(d and len(d) >= sz for d, (_, sz) in zip(data, reads)))
        if all_ok and canary_idx is not None:
            vtable_actual = struct.unpack_from(params[canary_idx].fmt,
                                                data[canary_idx][:params[canary_idx].size])[0]
            # Real vtable is a non-null .text pointer.  Zero means we caught
            # GDB in the wrong MMU context - retry.
            if vtable_actual == 0:
                time.sleep(0.2)
                continue
            if attempt > 0:
                print(f"  critical-params check: caught CHESS context on attempt {attempt+1}",
                      flush=True)
            break
        elif all_ok:
            # No canary registered (shouldn't happen) - fall through.
            if attempt > 0:
                print(f"  critical-params check: caught CHESS context on attempt {attempt+1}",
                      flush=True)
            break
        time.sleep(0.2)
    else:
        print(f"  WARNING: critical-params read failed after {max_retries} retries "
              "- Layer-5 check skipped", flush=True)
        return []

    diverged: list[tuple[str, int, int]] = []
    for p, d in zip(params, data):
        actual = struct.unpack_from(p.fmt, d[:p.size])[0]
        if actual != p.expected:
            diverged.append((p.name, p.expected, actual))
    return diverged
