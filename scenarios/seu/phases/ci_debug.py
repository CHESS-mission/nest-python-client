"""Phase: CI-DEBUG — run the full CI oracle pipeline on user-specified targets.

Combines all SEU detection layers in a single phase:

  1. CRASH      — vCPU silence / kernel panic (event oracle + 5 s liveness)
  2. DETECTED   — FPrime HLTH_PING_WARN / FATAL events (event oracle)
  3. MASKED     — bit-flip silently tolerated, FS keeps running normally
  4. PAIRWISE   — EA x OBC state-machine invariant violation (PairwiseHook)
  5. GOLDEN    — silent-corruption candidates: MASKED outcomes whose event
                 stream diverges from a baseline 'golden' fingerprint
                 captured before any injection runs

The pipeline is identical to --ci's; only target selection and the extra
golden-run divergence check differ.
"""

from __future__ import annotations

import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from nest_client.seu.elf_analyzer import (
    analyze_cached as analyze,
    expand_symbol_fields,
    SymbolInfo, FieldInfo,
)
import struct
from nest_client.seu.injector import (
    CampaignConfig, SEUCampaign, InjectionSpec, InjectionResult,
    PtyOracle, GdbMemWriter, FaultInjectorClient,
)
from nest_client.seu.critical_params import (
    CriticalParam, build_health_critical_params, check_critical_params,
)

import os
from ..config import (
    ELF_PATH, SOCK_PATH, SEU_DB, RESULTS,
    _docker_mode, PTY_LOG, CONSOLE_LOG, GDB_HOST, NEST_URL,
)

# Optional stable ELF for runtime-address resolution (BSS matches running QEMU process).
# Set via CHESS_STABLE_ELF_PATH env var; absent = fall back to ELF_PATH addresses.
_STABLE_ELF_PATH: Path | None = (
    Path(os.environ["CHESS_STABLE_ELF_PATH"])
    if os.environ.get("CHESS_STABLE_ELF_PATH") else None
)
from ..helpers import print_banner, wait_for_beacon, ensure_beacon
from ..pairwise import PairwiseHook


# golden run fingerprinting

# Parse an FPrime event line:
#   "[<vmtime>] EVENT: (<id>) (<ts>) <SEVERITY>: (<component>) <EventType> : <args>"
_EVENT_RE = re.compile(
    r"EVENT:.*?(?P<sev>WARNING_HI|WARNING_LO|FATAL|ACTIVITY_HI|ACTIVITY_LO|DIAGNOSTIC)"
    r":\s*\((?P<comp>\w+)\)\s+(?P<etype>\w+)")
_PAYLOAD_RE = re.compile(r"PACKET_SENT\s*:\s*Packet sent with payload\s+(\d+)")


@dataclass
class GoldenFingerprint:
    signatures: set[tuple[str, str, str]] = field(default_factory=set)  # (sev, component, etype)
    payload_seen: bool = False
    sample_count:  int = 0
    sample_window_s: float = 0.0


# Layer-5 GOLDEN integrity check infrastructure now lives in
# nest_client.seu.critical_params and is consumed by SEUCampaign itself, so the
# same Layer-5 logic runs in --ci and --ci-debug.  See imports above.


def _event_signatures(lines: list[str]) -> set[tuple[str, str, str]]:
    sigs: set[tuple[str, str, str]] = set()
    for ln in lines:
        m = _EVENT_RE.search(ln or "")
        if m:
            sigs.add((m.group("sev"), m.group("comp"), m.group("etype")))
    return sigs


def _wait_health_readable(gdb: "GdbMemWriter", npe_addr: int,
                          max_tries: int = 120) -> bool:
    """Poll m_numPingEntries until it reads a sane value in the caught MMU
    context, so the subsequent health write actually lands.

    After a per-injection system_reset the health page may not be paged in /
    initialised yet, and a random GDB halt often catches a non-CHESS context -
    the write then silently misses and a DETECTED is mis-recorded as MASKED.
    Confirming a sane read first means CHESS health context is live; the write
    that follows (itself retry-verified) then catches it.  Jittered to avoid
    aliasing with the ~1 Hz schedule.  Returns True once health is readable.
    """
    import random as _rnd
    for _ in range(max_tries):
        rb  = gdb.read_bulk([(npe_addr, 2)])
        npe = (struct.unpack_from("<H", rb[0][:2])[0]
               if rb and rb[0] and len(rb[0]) >= 2 else -1)
        if 1 <= npe <= 64:        # MAX_HEALTH_SLOTS-class sanity bound
            return True
        time.sleep(0.15 + _rnd.random() * 0.25)
    return False


def _capture_golden(oracle: PtyOracle, duration_s: float = 10.0) -> GoldenFingerprint:
    """Sample CHESS's normal event stream to build a behavioural fingerprint."""
    print(f"\n  Capturing golden fingerprint ({duration_s:.0f}s of clean run)…", flush=True)
    oracle.drain()
    time.sleep(duration_s)
    lines = oracle.recent_lines(2000)
    events = [l for l in lines if "EVENT:" in l]
    sigs = _event_signatures(events)
    payload_seen = any(_PAYLOAD_RE.search(l) for l in events)
    fp = GoldenFingerprint(
        signatures      = sigs,
        payload_seen    = payload_seen,
        sample_count    = len(events),
        sample_window_s = duration_s,
    )
    print(f"  Golden: {fp.sample_count} EVENT lines, "
          f"{len(fp.signatures)} unique (sev,component,event) signatures, "
          f"PACKET_SENT={'yes' if payload_seen else 'NO'}", flush=True)
    return fp


def _silent_corruption_check_unused(result,
                                    golden: GoldenFingerprint,
                                    critical: list[CriticalParam] | None = None,
                                    gdb=None) -> str | None:
    """DEAD CODE — kept only to document the previous Layer-5 design.

    Layer-5 now lives in SEUCampaign.run_targets (per-injection check) and
    SEUCampaign.print_summary (report).  This function has no callers; kept
    here so the design rationale doesn't disappear.  Delete in a follow-up.
    """
    # (heartbeat-lost / novel-WARN backstops — see SEUCampaign for current path)
    last = result.last_events or []
    if golden.payload_seen and not any("PACKET_SENT" in (l or "") for l in last):
        return "no PACKET_SENT in tail (heartbeat lost)"
    tail_sigs = _event_signatures(last)
    novel = tail_sigs - golden.signatures
    if novel:
        interesting = {s for s in novel if s[0] in
                       ("WARNING_HI", "WARNING_LO", "FATAL")}
        if interesting:
            sig = next(iter(interesting))
            return f"novel event signature {sig}"
    return None


# GDB direct-write injection

def _run_gdb_write(target: dict,
                   gdb_host: str,
                   oracle: PtyOracle,
                   observation_window_s: float,
                   liveness_timeout_s: float,
                   delay_s: float = 1.0) -> InjectionResult:
    """
    Write a specific 4-byte LE value to `target['addr']` via GDB with
    retry-verify, then run the event oracle for the observation window.

    Uses the same retry-verify pattern as --hard-crash and --detected so the
    write reliably lands even when the CPU was paused outside CHESS's process
    context.  Returns an InjectionResult compatible with the campaign results
    so the 5-layer report can include both bit-flip and write outcomes.
    """
    addr  = target["addr"]
    value = target["write_value"]
    spec  = InjectionSpec(
        addr        = addr,
        bit         = 0,                          # not meaningful for write
        delay       = 0,
        symbol      = target.get("symbol", ""),
        byte_offset = target.get("byte_offset", 0),
        field_name  = target.get("field", ""),
    )

    gdb = GdbMemWriter(host=gdb_host, port=1234)
    gdb.LIVENESS_TIMEOUT_S = liveness_timeout_s   # propagate (matches oracle)
    oracle.LIVENESS_TIMEOUT_S = liveness_timeout_s

    # Read original value (best-effort; may be None if GDB halts outside ctx).
    rb = gdb.read_bulk([(addr, 4)])
    orig_val = (struct.unpack_from('<I', rb[0])[0]
                if rb and rb[0] and len(rb[0]) >= 4 else 0)
    print(f"  GDB write: 0x{addr:08x} ← {value} (orig={orig_val})", flush=True)

    # Clear stale events BEFORE writing so anything FPrime emits afterward
    # (e.g. HLTH_PING_WARN on the next health tick) lands in a clean buffer.
    oracle.drain()

    # Retry-verify the write — same loop as --hard-crash.
    t0 = time.monotonic()
    verified = False
    for attempt in range(30):
        gdb.writes_and_reads(writes=[(addr, value)], reads=[])
        rb = gdb.read_bulk([(addr, 4)])
        if rb and rb[0] and len(rb[0]) >= 4:
            v = struct.unpack_from('<I', rb[0])[0]
            if v == value:
                verified = True
                print(f"  Write landed (attempt {attempt+1}): "
                      f"0x{addr:08x}={value} ✓", flush=True)
                break
        time.sleep(0.1)
    if not verified:
        print(f"  WARNING: write never verified after 30 attempts", flush=True)

    # Observe for the full window — DO NOT drain again, or we'd discard the
    # very event we're waiting for.  HLTH_PING_WARN typically fires within
    # 1-2 s of a cycleCount injection; FATAL within 1-2 s of cycleCount>>fatal.
    verdict = oracle.classify(observation_window_s * 0.5)

    elapsed = time.monotonic() - t0
    return InjectionResult(
        spec         = spec,
        trigger_insn = 0,                          # not applicable for GDB write
        success      = verified,
        original     = orig_val & 0xff,
        flipped      = value & 0xff,
        elapsed_s    = round(elapsed, 2),
        outcome      = verdict.get("outcome", "MASKED"),
        evidence     = verdict.get("evidence", ""),
        last_events  = verdict.get("last_events", []),
    )


# synthetic HLTH_PING_WARN target (ELF-derived health cycleCount address)
#
# PingTracker layout inside CdhCore::health.m_pingTrackerEntries (DWARF-verified):
#   m_pingTrackerEntries array starts at offset 7080 from health base
#   Per-entry size: 296 bytes
#   Within each entry:
#     +0:   PingEntry (warnCycles U64 LE=3, fatalCycles U64 LE=5, entryName Fw::String)
#     +280: cycleCount (U32)
#     +284: key (U32)
_PING_ENTRY_ARRAY_OFFSET = 7080
_PING_CC_OFF             = 280   # cycleCount within each PingTracker entry (+280)
_PING_FC_OFF             = 8     # fatalCycles within each PingTracker entry (+8, U64 LE)
_PING_WARN_CYCLES        = 3
_PING_FATAL_CYCLES       = 6     # written to cycleCount; paired with fatalCycles=1
_PING_HEALTH_WAIT_S      = 12.0  # one Health::Run cycle (4 s) × 3 to guarantee a check
_PING_CRASH_WAIT_S       = 12.0  # same window; FATAL fires within one 4 s tick
_PING_STEP               = 0x800
_PING_WARN_SIGN = struct.pack("<Q", 3) + struct.pack("<Q", 5)   # warnCycles + fatalCycles U64


def _find_health_cyclecount_addr(syms: list[SymbolInfo],
                                 gdb: "GdbMemWriter | None" = None) -> tuple[int, str] | None:
    """Return (cycleCount_addr, label) for the first active PingTracker entry.

    Prefers the stable ELF (CHESS_STABLE_ELF_PATH) for address resolution because
    the debug ELF and the running binary have divergent BSS layouts: the debug ELF
    has extra DWARF metadata that shifts BSS above ~0x130000, so its health address
    does not match the runtime process.  The stable ELF has the correct addresses.

    When *gdb* is provided, scans health BSS at runtime to find a PingTracker
    that matches (warnCycles=3, fatalCycles=5) and has a non-empty component name.
    Falls back to the ELF-derived address for entry[0] if the scan yields nothing.
    """
    # Try stable ELF first (runtime-correct addresses); fall back to debug ELF syms.
    if _STABLE_ELF_PATH is not None and _STABLE_ELF_PATH.exists():
        try:
            stable_syms = analyze(_STABLE_ELF_PATH)
            health = next((s for s in stable_syms
                           if "health" in s.demangled.lower()
                           and "CdhCore" in s.demangled
                           and "pingEntries" not in s.demangled
                           and s.section == ".bss"), None)
            if health:
                print(f"  Using stable ELF address for health: 0x{health.address:08x}", flush=True)
        except Exception:
            health = None
    else:
        health = None

    if health is None:
        health = next((s for s in syms
                       if "health" in s.demangled.lower()
                       and "CdhCore" in s.demangled
                       and "pingEntries" not in s.demangled
                       and s.section == ".bss"), None)
    if health is None:
        return None

    if gdb is not None:
        base, size = health.address, health.size
        buf = b""
        off = 0
        while off < size:
            chunk = min(_PING_STEP, size - off)
            data = b"".join(gdb.read_bulk([(base + off, chunk)]))
            buf += data if data else b"\x00" * chunk
            off += chunk

        search_start = 0
        while True:
            i = buf.find(_PING_WARN_SIGN, search_start)
            if i < 0:
                break
            name_start = i + 20
            name_end   = buf.find(b"\x00", name_start)
            if name_end < 0:
                name_end = name_start + 64
            raw = buf[name_start:min(name_end, name_start + 64)]
            comp_name = raw.decode("ascii", errors="replace").strip()
            if comp_name and comp_name.isprintable() and len(comp_name) > 2:
                cc_addr = base + i + _PING_CC_OFF
                return cc_addr, comp_name
            search_start = i + 1

    # Fallback: ELF-computed address for entry[0]
    cc_addr = health.address + _PING_ENTRY_ARRAY_OFFSET + _PING_CC_OFF
    return cc_addr, f"entry[0] @ 0x{cc_addr:08x}"


def _run_hlth_ping_warn(syms: list[SymbolInfo],
                        gdb_host: str,
                        fi_sock,
                        oracle: PtyOracle,
                        liveness_timeout_s: float) -> InjectionResult:
    """Inject cycleCount=warnCycles into a Health PingTracker, wait for HLTH_PING_WARN.

    Mirrors the approach in detected.py: write once, wait for Health::Run to fire,
    confirm via cycleCount read-back AND oracle event stream.  Resets cycleCount
    to 0 afterward to prevent the follow-on HLTH_PING_LATE FATAL.
    """
    _gdb = GdbMemWriter(host=gdb_host, port=1234)

    # Try BSS scan first; fallback to ELF offset
    hit = _find_health_cyclecount_addr(syms, gdb=_gdb)
    if hit is None:
        hit = _find_health_cyclecount_addr(syms, gdb=None)
    if hit is None:
        return InjectionResult(
            spec=InjectionSpec(addr=0, bit=0, delay=0,
                               symbol="CdhCore::health", byte_offset=0,
                               field_name="cycleCount"),
            trigger_insn=0, success=False, original=0, flipped=0, elapsed_s=0.0,
            outcome="MASKED", evidence="health symbol not found in ELF",
            last_events=[],
        )

    cc_addr, comp_name = hit

    _health_base = cc_addr - _PING_ENTRY_ARRAY_OFFSET - _PING_CC_OFF
    _npe_addr    = _health_base + 14480   # m_numPingEntries (U16, DWARF-verified offset)
    print(f"  Health cycleCount addr: 0x{cc_addr:08x}  health_base: 0x{_health_base:08x}", flush=True)

    # Gate on health being readable before writing, else the write silently
    # misses (wrong MMU context / health not yet paged in after reset) and the
    # WARN is mis-recorded as MASKED.
    if not _wait_health_readable(_gdb, _npe_addr):
        print("  WARNING: health page not readable after gate — write may miss", flush=True)

    spec = InjectionSpec(addr=cc_addr, bit=0, delay=0,
                         symbol=f"CdhCore::health (PingTracker[{comp_name}])",
                         byte_offset=0, field_name="cycleCount")

    # Read original cycleCount
    rb = _gdb.read_bulk([(cc_addr, 4)])
    orig = struct.unpack_from("<I", rb[0])[0] if rb and rb[0] and len(rb[0]) >= 4 else 0
    print(f"  GDB write: 0x{cc_addr:08x} ← {_PING_WARN_CYCLES} (orig={orig})", flush=True)

    oracle.drain()

    # Write cycleCount=warnCycles with retry-verify against the wrong-MMU-context
    # failure mode: GDB may halt the vCPU in a kernel/ISR window where CHESS's
    # userspace page is not mapped, so the M/m pair targets a stale TLB entry.
    # write_u32_verified resumes-and-retries until the read-back matches, same
    # pattern as write_byte uses for the sweep's bit-flips.  m_numPingEntries
    # is read in the same halt window as the verification read.
    t0 = time.monotonic()
    write_ok, cc_post_write, extras = _gdb.write_u32_verified(
        cc_addr, _PING_WARN_CYCLES,
        extra_reads=[(_npe_addr, 4)],
    )
    _npe_raw = extras[0] if extras else b""
    _npe_val = struct.unpack_from("<H", _npe_raw[:2])[0] if len(_npe_raw) >= 2 else -1
    print(f"  cycleCount post-write: {cc_post_write}  m_numPingEntries: {_npe_val}", flush=True)
    if not write_ok:
        print(f"  WARNING: write did not verify after retries (cc_post_write={cc_post_write})",
              flush=True)
    # writes_and_reads sends 'c' but QEMU 10.x sometimes leaves the CPU halted
    # if the ACK doesn't arrive in time.  resume_cpu is idempotent (no-op if
    # already running) and clears that race before the observation window.
    _gdb.resume_cpu()

    # 2 s instruction-count crash check.  Unconditional now that write_ok is
    # the only signal for "did the write land" — the insn count tells us
    # whether the vCPU is actually executing CHESS in the observation window.
    _crash_by_count = False
    _insn_delta = -1
    if fi_sock is not None:
        try:
            with FaultInjectorClient(fi_sock) as _fi:
                _c0 = _fi.get_count()
                time.sleep(2.0)
                _c1 = _fi.get_count()
            _insn_delta = _c1 - _c0
            print(f"  insn delta over 2s: {_insn_delta:,}", flush=True)
            if _insn_delta < 500_000:
                _crash_by_count = True
                print("  vCPU halted → CRASH (instruction count)", flush=True)
        except Exception as _e:
            print(f"  WARNING: insn count check failed: {_e}", flush=True)
            time.sleep(2.0)
    else:
        time.sleep(2.0)   # maintain same timing as --ci even without the check

    if _crash_by_count:
        # Best-effort reset in case the vCPU is only briefly halted and CHESS
        # would otherwise see cycleCount=warnCycles on the next tick.  Same
        # verified-write helper as the success path.
        _gdb.write_u32_verified(cc_addr, 0)
        _gdb.resume_cpu()
        elapsed = time.monotonic() - t0
        return InjectionResult(
            spec=spec, trigger_insn=0, success=(cc_post_write == _PING_WARN_CYCLES),
            original=orig & 0xff, flipped=_PING_WARN_CYCLES & 0xff,
            elapsed_s=round(elapsed, 2),
            outcome="CRASH",
            evidence=f"[insn count] delta={_insn_delta:,} over 2s — vCPU halted",
            last_events=[],
        )

    # vCPU alive run the event oracle for the full window (same as --ci).
    # Do NOT subtract the 2 s from the oracle budget; health events need time.
    oracle.LIVENESS_TIMEOUT_S = liveness_timeout_s
    verdict = oracle.classify(_PING_HEALTH_WAIT_S)

    # Read back cycleCount: if Run fired → incremented past warnCycles.
    rb3 = _gdb.read_bulk([(cc_addr, 4)])
    cc_final = struct.unpack_from("<I", rb3[0])[0] if rb3 and rb3[0] and len(rb3[0]) >= 4 else -1
    print(f"  cycleCount final: {cc_final}  (expected ≠{_PING_WARN_CYCLES} if WARN fired)",
          flush=True)

    # Reset cycleCount to prevent the follow-on HLTH_PING_LATE FATAL.
    # Verified write: a silent failure here lets the next Health::Run see
    # cycleCount > fatalCycles and crash CHESS before the campaign moves on.
    _gdb.write_u32_verified(cc_addr, 0)
    _gdb.resume_cpu()
    print("  cycleCount reset to 0", flush=True)

    # Determine outcome: oracle event takes priority; fall back to cycleCount delta.
    outcome  = verdict.get("outcome", "MASKED")
    evidence = verdict.get("evidence", "")
    if outcome == "MASKED" and cc_post_write == _PING_WARN_CYCLES and cc_final not in (-1, _PING_WARN_CYCLES):
        outcome  = "DETECTED"
        evidence = (f"[GDB cycleCount] write={_PING_WARN_CYCLES}, "
                    f"advanced to {cc_final} → HLTH_PING_WARN fired")
        print(f"  ✓ WARN confirmed via cycleCount delta ({_PING_WARN_CYCLES} → {cc_final})",
              flush=True)

    elapsed = time.monotonic() - t0
    return InjectionResult(
        spec         = spec,
        trigger_insn = 0,
        success      = (cc_post_write == _PING_WARN_CYCLES),
        original     = orig & 0xff,
        flipped      = _PING_WARN_CYCLES & 0xff,
        elapsed_s    = round(elapsed, 2),
        outcome      = outcome,
        evidence     = evidence,
        last_events  = verdict.get("last_events", []),
    )


# synthetic HLTH_PING_FATAL target (vtable pointer corruption → CRASH)
#
# Writes 0 to health.address (the vtable pointer at C++ object offset 0).
# On ARM32, the first 4 bytes of any polymorphic object are the vtable pointer.
# Zeroing it means the next virtual dispatch on the health object loads PC=0 →
# either illegal instruction or segfault → CHESS dies within one Health::Run
# tick (≤ 4 s).  No PingReturn race — vtable is not touched by any component
# response.  Requires the no_phoenix (seu-debug) topology.

def _run_hlth_ping_fatal(syms: list[SymbolInfo],
                         gdb_host: str,
                         fi_sock,
                         oracle: PtyOracle,
                         liveness_timeout_s: float) -> InjectionResult:
    """Inject cycleCount > fatalCycles into Health PingTracker → HLTH_PING_LATE FATAL → CRASH."""
    _gdb = GdbMemWriter(host=gdb_host, port=1234)

    hit = _find_health_cyclecount_addr(syms, gdb=_gdb)
    if hit is None:
        hit = _find_health_cyclecount_addr(syms, gdb=None)
    if hit is None:
        return InjectionResult(
            spec=InjectionSpec(addr=0, bit=0, delay=0,
                               symbol="CdhCore::health", byte_offset=0,
                               field_name="cycleCount"),
            trigger_insn=0, success=False, original=0, flipped=0, elapsed_s=0.0,
            outcome="MASKED", evidence="health symbol not found in ELF",
            last_events=[],
        )

    cc_addr, comp_name = hit
    _health_base = cc_addr - _PING_ENTRY_ARRAY_OFFSET - _PING_CC_OFF
    vtable_addr  = _health_base    # C++ vtable pointer is at object offset 0
    print(f"  health_base: 0x{_health_base:08x}  vtable ptr addr: 0x{vtable_addr:08x}",
          flush=True)

    # Gate on health being readable so the vtable write lands (else a "CRASH"
    # could come from a halted vCPU rather than the intended virtual-dispatch
    # fault, or the write misses and we mis-record MASKED).
    if not _wait_health_readable(_gdb, _health_base + 14480):
        print("  WARNING: health page not readable after gate — write may miss", flush=True)

    spec = InjectionSpec(addr=vtable_addr, bit=0, delay=0,
                         symbol="CdhCore::health (vtable ptr)",
                         byte_offset=0, field_name="vtable")

    rb = _gdb.read_bulk([(vtable_addr, 4)])
    orig_vtable = struct.unpack_from("<I", rb[0])[0] if rb and rb[0] and len(rb[0]) >= 4 else 0
    print(f"  GDB write: 0x{vtable_addr:08x} ← 0  "
          f"(null vtable → crash on next virtual call, orig=0x{orig_vtable:08x})", flush=True)

    oracle.drain()
    t0 = time.monotonic()

    # Zero the vtable pointer with retry-verify: same wrong-MMU-context failure
    # mode as HLTH_PING_WARN.  Without the retry the write may not land, and
    # the resulting "CRASH" would come from a halted vCPU rather than the
    # intended virtual-dispatch fault — right answer for the wrong reason.
    write_ok, vt_post, _ = _gdb.write_u32_verified(vtable_addr, 0)
    print(f"  vtable ptr post-write: 0x{vt_post & 0xffffffff:08x}  "
          f"(expect 0x00000000)", flush=True)
    if not write_ok:
        print(f"  WARNING: vtable write did not verify after retries", flush=True)
    _gdb.resume_cpu()  # clear QEMU-10 stuck-halt race

    # 2 s instruction-count crash check.  Health::Run fires every Run-tick
    # (1 s on Pathfinder0FS rg2).  Fast path: the very next virtual dispatch
    # crashes during this window → low insn delta → CRASH.  Slow path: the
    # crash lands after the window → oracle liveness catches the silence.
    _crash_by_count = False
    _insn_delta = -1
    if fi_sock is not None:
        try:
            with FaultInjectorClient(fi_sock) as _fi:
                _c0 = _fi.get_count()
                time.sleep(2.0)
                _c1 = _fi.get_count()
            _insn_delta = _c1 - _c0
            print(f"  insn delta over 2s: {_insn_delta:,}", flush=True)
            if _insn_delta < 500_000:
                _crash_by_count = True
                print("  vCPU halted → CRASH (instruction count)", flush=True)
        except Exception as _e:
            print(f"  WARNING: insn count check failed: {_e}", flush=True)
            time.sleep(2.0)
    else:
        time.sleep(2.0)

    if _crash_by_count:
        elapsed = time.monotonic() - t0
        return InjectionResult(
            spec=spec, trigger_insn=0, success=(vt_post == 0),
            original=orig_vtable & 0xff, flipped=0x00,
            elapsed_s=round(elapsed, 2),
            outcome="CRASH",
            evidence=f"[insn count] delta={_insn_delta:,} over 2s — vCPU halted",
            last_events=[],
        )

    # vCPU still alive 2 s after write FATAL fires later (slow path).
    # Oracle with liveness_timeout catches the subsequent silence.
    oracle.LIVENESS_TIMEOUT_S = liveness_timeout_s
    verdict = oracle.classify(_PING_CRASH_WAIT_S)

    elapsed = time.monotonic() - t0
    outcome  = verdict.get("outcome", "MASKED")
    evidence = verdict.get("evidence", "")
    print(f"  -> outcome={outcome}  elapsed={elapsed:.1f}s", flush=True)

    return InjectionResult(
        spec         = spec,
        trigger_insn = 0,
        success      = (vt_post == 0),
        original     = orig_vtable & 0xff,
        flipped      = 0x00,
        elapsed_s    = round(elapsed, 2),
        outcome      = outcome,
        evidence     = evidence,
        last_events  = verdict.get("last_events", []),
    )


# synthetic MASKED targets (verified vs silent-corruption suspect)
#
# Both use the same observation window (12 s).  Different writes, different
# real-world effects:
#
#   MASKED_BENIGN     : write 0 to entry[5].cycleCount.  CycleCount naturally
#                       oscillates 0↔1 between Health::Run ticks and PingReturn
#                       resets, so this is a true no-op.  CHESS unaffected →
#                       MASKED *verified*.
#
#   MASKED_HEARTBEAT  : write a large divisor (100) to rateGroup1.divisor in
#                       CHESS::rateGroupDivisorsSet.  Slows the 1 Hz rate group
#                       by ~100×, so the Transceiver's schedIn handler fires
#                       only every ~100 s instead of every 1 s — PACKET_SENT
#                       disappears from the event stream within the observation
#                       window.  Health::Run (on rateGroup3, unaffected) won't
#                       fire WARN until cycleCount==warnCycles=3, which takes
#                       3 × 4 s = 12 s and only IF rateGroup1 components stay
#                       silent the whole time, so the WARN lands at the very
#                       edge of the window.  Result: MASKED (no WARN seen) +
#                       no PACKET_SENT in tail → Layer-5 GOLDEN heartbeat-lost
#                       branch → MASKED *suspect*.
#
# Both demonstrate real silent-corruption scenarios that --ci would catch.

_MASKED_TARGET_ENTRY    = 5         # benign entry — no impact on operation
_MASKED_ENTRY_SIZE      = 296       # bytes per PingTracker
_MASKED_WAIT_S          = 12.0      # same observation window for both
_RG1_DIVISOR_NEW        = 1000      # period ≈ 100 s — guarantees PACKET_SENT silence in the 14 s window


def _find_rg1_divisor_addr(syms: list[SymbolInfo],
                            gdb: "GdbMemWriter | None" = None) -> int | None:
    """Locate &CHESS::rateGroupDivisorsSet[0].divisor (source constant in .bss).

    NOTE: this is the *source* DivisorSet passed to RateGroupDriverImpl::configure().
    The driver copies it into its private m_divisorSet at init, so writes to this
    address don't actually slow rateGroup1 at runtime — they're observed only by
    code that re-reads the source (none in CHESS).  Heartbeat suppression via
    divisor corruption would need the driver's internal copy, which requires
    DWARF for accurate offset resolution (a runtime byte-pattern scan is too
    fragile: the first U32==10 inside the driver object is usually some other
    load-bearing field that crashes CHESS when changed).
    """
    candidates_path = _STABLE_ELF_PATH if _STABLE_ELF_PATH and _STABLE_ELF_PATH.exists() else None
    use_syms = analyze(candidates_path) if candidates_path else syms
    s = next((s for s in use_syms
              if s.section == ".bss"
              and "rateGroupDivisorsSet" in s.demangled), None)
    return s.address if s else None


def _run_masked_benign(syms: list[SymbolInfo],
                       gdb_host: str,
                       fi_sock,
                       oracle: PtyOracle,
                       liveness_timeout_s: float) -> InjectionResult:
    """Write 0 to entry[5].cycleCount — true no-op, CHESS unaffected → MASKED verified."""
    _gdb = GdbMemWriter(host=gdb_host, port=1234)

    hit = _find_health_cyclecount_addr(syms, gdb=None)
    if hit is None:
        return InjectionResult(
            spec=InjectionSpec(addr=0, bit=0, delay=0,
                               symbol="CdhCore::health", byte_offset=0,
                               field_name="cycleCount"),
            trigger_insn=0, success=False, original=0, flipped=0, elapsed_s=0.0,
            outcome="MASKED", evidence="health symbol not found in ELF",
            last_events=[],
        )

    cc_addr_e0, _ = hit
    cc_addr = cc_addr_e0 + _MASKED_TARGET_ENTRY * _MASKED_ENTRY_SIZE

    spec = InjectionSpec(addr=cc_addr, bit=0, delay=0,
                         symbol=f"CdhCore::health (entry[{_MASKED_TARGET_ENTRY}].cycleCount)",
                         byte_offset=0, field_name="cycleCount")
    print(f"  MASKED_BENIGN: entry[{_MASKED_TARGET_ENTRY}].cycleCount @ 0x{cc_addr:08x}  "
          f"window={_MASKED_WAIT_S}s", flush=True)

    rb = _gdb.read_bulk([(cc_addr, 4)])
    orig = struct.unpack_from("<I", rb[0])[0] if rb and rb[0] and len(rb[0]) >= 4 else 0
    print(f"  GDB write: 0x{cc_addr:08x} ← 0  (no-op; orig={orig})", flush=True)

    oracle.drain()
    t0 = time.monotonic()

    # Retry-verify: resilient to transient GDB kernel-context halts post-reset.
    cc_post = -1
    for attempt in range(30):
        _gdb.writes_and_reads(writes=[(cc_addr, 0)], reads=[])
        rb_verify = _gdb.read_bulk([(cc_addr, 4)])
        if rb_verify and rb_verify[0] and len(rb_verify[0]) >= 4:
            cc_post = struct.unpack_from("<I", rb_verify[0])[0]
            if cc_post == 0:
                if attempt > 0:
                    print(f"  write landed on attempt {attempt+1}", flush=True)
                break
        time.sleep(0.1)
    print(f"  cycleCount post-write: {cc_post}", flush=True)

    return _classify_masked(spec, orig, cc_post, _gdb, fi_sock, oracle,
                            liveness_timeout_s, t0)


def _run_masked_heartbeat(syms: list[SymbolInfo],
                          gdb_host: str,
                          fi_sock,
                          oracle: PtyOracle,
                          liveness_timeout_s: float) -> InjectionResult:
    """Write large divisor to rateGroup1 → suppress PACKET_SENT → MASKED suspect (heartbeat lost)."""
    _gdb = GdbMemWriter(host=gdb_host, port=1234)

    div_addr = _find_rg1_divisor_addr(syms)
    if div_addr is None:
        return InjectionResult(
            spec=InjectionSpec(addr=0, bit=0, delay=0,
                               symbol="CHESS::rateGroupDriver.m_divisorSet", byte_offset=0,
                               field_name="divisor"),
            trigger_insn=0, success=False, original=0, flipped=0, elapsed_s=0.0,
            outcome="MASKED", evidence="rateGroupDriver runtime divisor not found",
            last_events=[],
        )

    spec = InjectionSpec(addr=div_addr, bit=0, delay=0,
                         symbol="CHESS::rateGroupDriver.m_divisorSet[0].divisor (runtime)",
                         byte_offset=0, field_name="divisor")
    print(f"  MASKED_HEARTBEAT: rg1.divisor @ 0x{div_addr:08x}  "
          f"window={_MASKED_WAIT_S}s", flush=True)

    rb = _gdb.read_bulk([(div_addr, 4)])
    orig = struct.unpack_from("<I", rb[0])[0] if rb and rb[0] and len(rb[0]) >= 4 else 0
    print(f"  GDB write: 0x{div_addr:08x} ← {_RG1_DIVISOR_NEW}  "
          f"(stall rg1 to suppress PACKET_SENT, orig divisor={orig})", flush=True)

    oracle.drain()
    t0 = time.monotonic()

    _rb_write = _gdb.writes_and_reads(
        writes=[(div_addr, _RG1_DIVISOR_NEW)],
        reads=[(div_addr, 4)],
    )
    _d_raw = _rb_write[0] if _rb_write and _rb_write[0] else b""
    d_post = struct.unpack_from("<I", _d_raw)[0] if len(_d_raw) >= 4 else -1
    print(f"  rg1.divisor post-write: {d_post}", flush=True)

    return _classify_masked(spec, orig, d_post, _gdb, fi_sock, oracle,
                            liveness_timeout_s, t0)


def _classify_masked(spec, orig, post, gdb, fi_sock, oracle,
                     liveness_timeout_s, t0) -> InjectionResult:
    """Shared 2s insn-count + 12s oracle classification for MASKED synthetics."""
    _gdb_ok = (post != -1)
    _crash_by_count = False
    _insn_delta = -1
    if fi_sock is not None and _gdb_ok:
        try:
            with FaultInjectorClient(fi_sock) as _fi:
                _c0 = _fi.get_count()
                time.sleep(2.0)
                _c1 = _fi.get_count()
            _insn_delta = _c1 - _c0
            print(f"  insn delta over 2s: {_insn_delta:,}", flush=True)
            if _insn_delta < 500_000:
                _crash_by_count = True
        except Exception as _e:
            print(f"  WARNING: insn count check failed: {_e}", flush=True)
            time.sleep(2.0)
    else:
        time.sleep(2.0)

    if _crash_by_count:
        elapsed = time.monotonic() - t0
        return InjectionResult(
            spec=spec, trigger_insn=0, success=True,
            original=orig & 0xff, flipped=0x00,
            elapsed_s=round(elapsed, 2),
            outcome="CRASH",
            evidence=f"[insn count] delta={_insn_delta:,} over 2s — unexpected for this target",
            last_events=[],
        )

    oracle.LIVENESS_TIMEOUT_S = liveness_timeout_s
    verdict = oracle.classify(_MASKED_WAIT_S)

    elapsed = time.monotonic() - t0
    outcome  = verdict.get("outcome", "MASKED")
    evidence = verdict.get("evidence", "")
    print(f"  -> outcome={outcome}  elapsed={elapsed:.1f}s", flush=True)

    return InjectionResult(
        spec         = spec,
        trigger_insn = 0,
        success      = True,
        original     = orig & 0xff,
        flipped      = 0x00,
        elapsed_s    = round(elapsed, 2),
        outcome      = outcome,
        evidence     = evidence,
        last_events  = verdict.get("last_events", []),
    )


# synthetic MASKED_SILENT_HEALTH_DISABLE (Layer-5 GOLDEN demo target)
#
# Writes warnCycles=1000 to entry[5] in CdhCore::health.m_pingTrackerEntries.
# Health::Run checks `cycleCount == warnCycles` (exact equality, FPrime source
# HealthComponentImpl.cpp:113).  With warnCycles=1000, cycleCount would need
# 1000 × 4 s ≈ 4000 s to walk to the threshold — unreachable within the 12 s
# observation window, so the oracle says MASKED.  The Layer-5 integrity check
# then reads warnCycles[5], sees 1000 ≠ 3 → MASKED suspect with precise evidence.
#
# Real-world equivalence: this corruption silently disables Health's warning
# monitor for that one entry's component.  If that component later hangs, no
# WARN ever fires — exactly the "silent corruption" failure mode Layer-5 exists
# to catch.

_MASKED_DISABLE_TARGET_ENTRY = 5      # which PingTracker entry to corrupt
_MASKED_DISABLE_WARN_NEW     = 1000   # huge value → unreachable within window


def _run_masked_silent_health_disable(syms: list[SymbolInfo],
                                       gdb_host: str,
                                       fi_sock,
                                       oracle: PtyOracle,
                                       liveness_timeout_s: float) -> InjectionResult:
    """Write warnCycles=1000 to entry[5] → silent de-monitoring → MASKED suspect."""
    _gdb = GdbMemWriter(host=gdb_host, port=1234)

    hit = _find_health_cyclecount_addr(syms, gdb=None)
    if hit is None:
        return InjectionResult(
            spec=InjectionSpec(addr=0, bit=0, delay=0,
                               symbol="CdhCore::health", byte_offset=0,
                               field_name="warnCycles"),
            trigger_insn=0, success=False, original=0, flipped=0, elapsed_s=0.0,
            outcome="MASKED", evidence="health symbol not found in ELF",
            last_events=[],
        )

    cc_addr_e0, _ = hit
    entry_base = cc_addr_e0 - _PING_CC_OFF + _MASKED_DISABLE_TARGET_ENTRY * _MASKED_ENTRY_SIZE
    wc_addr    = entry_base + 0   # warnCycles is at +0 within each PingTracker entry

    spec = InjectionSpec(addr=wc_addr, bit=0, delay=0,
                         symbol=f"CdhCore::health (entry[{_MASKED_DISABLE_TARGET_ENTRY}].entry.warnCycles)",
                         byte_offset=0, field_name="warnCycles")
    print(f"  MASKED_SILENT_HEALTH_DISABLE: warnCycles[{_MASKED_DISABLE_TARGET_ENTRY}] "
          f"@ 0x{wc_addr:08x}", flush=True)

    rb = _gdb.read_bulk([(wc_addr, 4)])
    orig = struct.unpack_from("<I", rb[0])[0] if rb and rb[0] and len(rb[0]) >= 4 else 0
    print(f"  GDB write: 0x{wc_addr:08x} ← {_MASKED_DISABLE_WARN_NEW}  "
          f"(silently disables Health WARN for entry[{_MASKED_DISABLE_TARGET_ENTRY}]; "
          f"orig={orig})", flush=True)

    oracle.drain()
    t0 = time.monotonic()

    # Retry-verify the write: separate GDB sessions are more resilient to
    # transient kernel-context halts than a single writes_and_reads.
    wc_post = -1
    for attempt in range(30):
        _gdb.writes_and_reads(writes=[(wc_addr, _MASKED_DISABLE_WARN_NEW)], reads=[])
        rb_verify = _gdb.read_bulk([(wc_addr, 4)])
        if rb_verify and rb_verify[0] and len(rb_verify[0]) >= 4:
            wc_post = struct.unpack_from("<I", rb_verify[0])[0]
            if wc_post == _MASKED_DISABLE_WARN_NEW:
                if attempt > 0:
                    print(f"  write landed on attempt {attempt+1}", flush=True)
                break
        time.sleep(0.1)
    print(f"  warnCycles post-write: {wc_post}", flush=True)

    return _classify_masked(spec, orig, wc_post, _gdb, fi_sock, oracle,
                            liveness_timeout_s, t0)


# Layer-5 builder + check are imported from nest_client.seu.critical_params and
# used by SEUCampaign itself (post-classify, pre-reset).  Both --ci and
# --ci-debug share the same code path.


# target spec parsing

def _parse_bits(s: str) -> list[int]:
    return [int(b.strip()) for b in s.split(",") if b.strip()]


def _label_addr(addr: int, symbols: list[SymbolInfo]) -> tuple[str, int]:
    for s in symbols:
        if s.address <= addr < s.address + max(s.size, 1):
            return s.demangled, addr - s.address
    return "", 0


def _resolve_symbol(pat: str, bits: list[int], symbols: list[SymbolInfo]) -> list[dict]:
    hits = [s for s in symbols if pat.lower() in s.demangled.lower()]
    if not hits:
        print(f"  WARNING: no symbol matching '{pat}' — skipping")
        return []
    if len(hits) > 1:
        names = [s.demangled for s in hits[:3]]
        print(f"  WARNING: '{pat}' matches {len(hits)} symbols — using first: {hits[0].demangled}")
        print(f"    others: {names[1:]}")
    s = hits[0]
    return [{"addr": s.address, "bit": b, "symbol": s.demangled,
             "byte_offset": 0, "field": ""} for b in bits]


def _resolve_field(sym_pat: str, field_name: str, bits: list[int],
                   symbols: list[SymbolInfo], elf_path: Path) -> list[dict]:
    hits = [s for s in symbols
            if sym_pat.lower() in s.demangled.lower() and s.section == ".bss"]
    if not hits:
        print(f"  WARNING: no BSS symbol matching '{sym_pat}' — skipping")
        return []
    if len(hits) > 1:
        print(f"  WARNING: '{sym_pat}' matches {len(hits)} — using first: {hits[0].demangled}")
    sym = hits[0]
    fields_map = expand_symbol_fields(elf_path, [sym])
    fields = fields_map.get(sym.name, [])
    matches = [f for f in fields if field_name.lower() in f.field_name.lower()]
    if not matches:
        avail = [f.field_name for f in fields[:10]]
        print(f"  WARNING: field '{field_name}' not found in {sym.demangled}")
        print(f"    Available fields: {avail}")
        return []
    if len(matches) > 1:
        print(f"  WARNING: '{field_name}' matches {len(matches)} fields — using first: {matches[0].field_name}")
    fi = matches[0]
    return [{"addr": sym.address + fi.offset, "bit": b,
             "symbol": sym.demangled, "byte_offset": fi.offset,
             "field": fi.field_name} for b in bits]


def _parse_spec(spec: str, symbols: list[SymbolInfo], elf_path: Path) -> list[dict]:
    """
    Parse one target spec string into a list of injection dicts.

    Bit-flip mode (FaultInjectorClient plugin, single-bit XOR at instruction N):
      0xADDR:BIT[,BIT]          raw hex address, auto-labelled from ELF
      SYMBOL:BIT[,BIT]          substring-match on demangled symbol name
      SYMBOL::FIELD:BIT[,BIT]   last '::' separates symbol from DWARF field name

    Direct-write mode (GDB write with retry-verify, reliable CRASH/DETECTED):
      0xADDR=VALUE              write 4-byte LE VALUE to ADDR (decimal or 0xHEX)
      SYMBOL=VALUE              write VALUE to symbol base
      SYMBOL::FIELD=VALUE       write VALUE to DWARF-resolved field
      Use this for targets whose semantics require a specific value
      (cycleCount=3 → DETECTED, cycleCount=100 → CRASH).

    Synthetic targets (resolved at injection time via GDB BSS scan):
      HLTH_PING_WARN            Health cycleCount injection → HLTH_PING_WARN WARNING
    """
    spec = spec.strip()
    if not spec or spec.startswith("#"):
        return []

    # Synthetic: HLTH_PING_WARN / HLTH_PING_FATAL
    if spec.upper() == "HLTH_PING_WARN":
        return [{"addr": 0, "bit": None,
                 "symbol": "CdhCore::health (PingTracker::cycleCount)",
                 "byte_offset": 0, "field": "cycleCount", "write_value": 3,
                 "synthetic": "HLTH_PING_WARN"}]

    if spec.upper() == "HLTH_PING_FATAL":
        return [{"addr": 0, "bit": None,
                 "symbol": "CdhCore::health (PingTracker::cycleCount)",
                 "byte_offset": 0, "field": "cycleCount", "write_value": _PING_FATAL_CYCLES,
                 "synthetic": "HLTH_PING_FATAL"}]

    if spec.upper() == "MASKED_BENIGN":
        return [{"addr": 0, "bit": None,
                 "symbol": f"CdhCore::health (entry[{_MASKED_TARGET_ENTRY}].cycleCount)",
                 "byte_offset": 0, "field": "cycleCount", "write_value": 0,
                 "synthetic": "MASKED_BENIGN"}]

    if spec.upper() == "MASKED_HEARTBEAT":
        return [{"addr": 0, "bit": None,
                 "symbol": "CHESS::rateGroupDivisorsSet[0] (rg1.divisor)",
                 "byte_offset": 0, "field": "divisor",
                 "write_value": _RG1_DIVISOR_NEW,
                 "synthetic": "MASKED_HEARTBEAT"}]

    if spec.upper() == "MASKED_SILENT_HEALTH_DISABLE":
        return [{"addr": 0, "bit": None,
                 "symbol": f"CdhCore::health (entry[{_MASKED_DISABLE_TARGET_ENTRY}].entry.warnCycles)",
                 "byte_offset": 0, "field": "warnCycles",
                 "write_value": _MASKED_DISABLE_WARN_NEW,
                 "synthetic": "MASKED_SILENT_HEALTH_DISABLE"}]

    # Direct-write specs (=VALUE)
    if "=" in spec:
        name_part, val_str = spec.rsplit("=", 1)
        try:
            value = int(val_str, 0)
        except ValueError:
            print(f"  WARNING: cannot parse value '{val_str}' in '{spec}'")
            return []
        m = re.match(r'^(0x[0-9a-fA-F]+|\d+)$', name_part)
        if m:
            addr = int(m.group(1), 0)
            sym_label, byte_off = _label_addr(addr, symbols)
            entries = [{"addr": addr, "bit": None, "symbol": sym_label,
                        "byte_offset": byte_off, "field": ""}]
        elif "::" in name_part:
            sym_pat, field_name = name_part.rsplit("::", 1)
            entries = _resolve_field(sym_pat, field_name, [0], symbols, elf_path)
            for e in entries:
                e["bit"] = None
        else:
            entries = _resolve_symbol(name_part, [0], symbols)
            for e in entries:
                e["bit"] = None
        for e in entries:
            e["write_value"] = value
        return entries

    # Bit-flip specs
    m = re.match(r'^(0x[0-9a-fA-F]+|\d+):([0-7](?:,[0-7])*)$', spec)
    if m:
        addr = int(m.group(1), 0)
        bits = _parse_bits(m.group(2))
        sym_label, byte_off = _label_addr(addr, symbols)
        return [{"addr": addr, "bit": b, "symbol": sym_label,
                 "byte_offset": byte_off, "field": "",
                 "write_value": None} for b in bits]

    m = re.match(r'^(.+):([0-7](?:,[0-7])*)$', spec)
    if not m:
        print(f"  WARNING: cannot parse '{spec}' — expected ADDR:BIT, NAME:BIT, or NAME=VALUE")
        return []

    name_part = m.group(1)
    bits = _parse_bits(m.group(2))

    if "::" in name_part:
        sym_pat, field_name = name_part.rsplit("::", 1)
        entries = _resolve_field(sym_pat, field_name, bits, symbols, elf_path)
    else:
        entries = _resolve_symbol(name_part, bits, symbols)
    for e in entries:
        e["write_value"] = None
    return entries


def _load_file(path: Path, symbols: list[SymbolInfo], elf_path: Path) -> list[dict]:
    targets: list[dict] = []
    for i, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.split("#")[0].strip()
        if not line:
            continue
        resolved = _parse_spec(line, symbols, elf_path)
        if not resolved:
            print(f"  (line {i}: '{line}' resolved to nothing)")
        targets.extend(resolved)
    return targets


# phase entry point

def run_ci_debug(args) -> None:
    """
    Run user-specified injection targets through the full CI oracle pipeline.

    Targets come from --targets (CLI) and/or --targets-file (one spec per line).
    Both may be used together; CLI specs are appended after file specs.

    In Docker mode the file path must be accessible inside the container
    (e.g. place it in ./seu_cache/ which is mounted at /tmp/seu_cache).
    """
    print_banner("SEU CI-DEBUG  user targets through CI oracle pipeline")

    if not ELF_PATH.exists():
        sys.exit(f"ERROR: ELF not found: {ELF_PATH}")

    syms = analyze(ELF_PATH)

    raw: list[dict] = []

    targets_file = getattr(args, "targets_file", None)
    if targets_file:
        p = Path(targets_file)
        if not p.exists():
            sys.exit(f"ERROR: --targets-file not found: {p}")
        print(f"  Loading targets from: {p}")
        raw.extend(_load_file(p, syms, ELF_PATH))

    for spec in getattr(args, "targets", None) or []:
        raw.extend(_parse_spec(spec, syms, ELF_PATH))

    if not raw:
        sys.exit("ERROR: no targets resolved — provide --targets or --targets-file")

    print(f"\n  {len(raw)} injection(s) to run:")
    for t in raw:
        label = f"{t['symbol']} :: {t['field']}" if t["field"] else (t["symbol"] or "(unlabeled)")
        if t.get("synthetic"):
            print(f"    (runtime BSS scan)  bit={t['bit']}  {label}")
        else:
            print(f"    0x{t['addr']:08x}  bit={t['bit']}  {label}")
    print()

    _oracle_log = CONSOLE_LOG if CONSOLE_LOG is not None else PTY_LOG
    _window = max(getattr(args, "window", 5.0), 20.0)

    _ea_sym  = next((s for s in syms if "eventAction"       in s.name and s.section == ".bss"), None)
    _obc_sym = next((s for s in syms if "obcSensorsManager" in s.name and s.section == ".bss"), None)
    _pairwise_hook = None
    if _ea_sym and _obc_sym:
        _pairwise_hook = PairwiseHook(
            ea_base_addr  = _ea_sym.address,
            obc_base_addr = _obc_sym.address,
            obc_state     = 4,             # assume NOMINAL
            stop_on_first = False,         # debug: report all violations, don't abort
        )
        print(f"  Pairwise hook: EA @ 0x{_ea_sym.address:08x}  OBC @ 0x{_obc_sym.address:08x}")
    else:
        print("  WARNING: pairwise hook skipped — EA or OBC symbol not found")

    cfg = CampaignConfig(
        socket_path             = SOCK_PATH,
        elf_path                = ELF_PATH,
        pty_log_path            = _oracle_log,
        delay_insn              = args.delay,
        observation_window_s    = _window,
        candidates_only         = False,
        results_path            = RESULTS,
        db_path                 = SEU_DB,
        use_insn_count_liveness = False,
        gdb_host                = GDB_HOST if _docker_mode else None,
        gdb_port                = 1234,
        nest_url                = NEST_URL if _docker_mode else None,
        classify_hook           = _pairwise_hook,
        # 5 s silence = CHESS dead. Safe because normal CHESS sends PACKET_SENT
        # every 1 s; only meaningful against the no_phoenix topology where CHESS
        # does not restart after a crash.
        liveness_timeout_s      = 5.0,
        # critical_params is set below after the boot wait the campaign engine
        # runs the Layer-5 integrity check itself, same code path as --ci.
        critical_params         = None,
    )
    campaign = SEUCampaign(cfg)
    run_id = campaign.start_db_run(
        topology="ci-debug",
        notes=f"targets: {len(raw)} specs",
    )

    if _docker_mode:
        campaign.setup_snapshot("chess_ready")

    # Layer 5: Golden run fingerprint (captured before any injection)
    # Starts the oracle directly so we can sample without going through the
    # campaign.  Reused by the silent-corruption check post-campaign.
    _golden_oracle = PtyOracle(_oracle_log)
    _golden_oracle.start()
    golden_duration = float(getattr(args, "golden_duration", 10.0))
    try:
        # Wait for CHESS to be active (FPrime emitting EVENT: lines) before
        # capturing the baseline. This is needed in Docker mode where NEST
        # reports "running" as soon as QEMU launches, but CHESS takes up to
        # 90 s more to boot and start the FPrime event loop.
        print("  Ensuring active CHESS beacon (PACKET_SENT advancing)…", flush=True)
        if ensure_beacon(_golden_oracle, GDB_HOST):
            print("  CHESS beacon active ✓", flush=True)
        else:
            print("  WARNING: beacon not advancing even after reset proceeding "
                  "(golden may be empty / first injection may false-CRASH)", flush=True)
        golden = _capture_golden(_golden_oracle, duration_s=golden_duration)
    finally:
        _golden_oracle.stop()

    # Layer-5 critical-params: build once, from clean RAM, share with the
    # campaign engine so the integrity check is identical to --ci's path
    if _docker_mode and GDB_HOST:
        try:
            _gdb_boot = GdbMemWriter(host=GDB_HOST, port=1234)
            cfg.critical_params = build_health_critical_params(syms, _gdb_boot)
            if cfg.critical_params:
                print(f"  Registered {len(cfg.critical_params)} critical params for "
                      f"Layer-5 GOLDEN integrity check (shared --ci path)", flush=True)
        except Exception as _e:
            print(f"  WARNING: critical-params build failed ({_e})", flush=True)

    # Split targets by injection mode.
    bitflip_targets = [t for t in raw if t.get("write_value") is None]
    write_targets   = [t for t in raw if t.get("write_value") is not None]

    if bitflip_targets:
        print(f"\n  Bit-flip injections ({len(bitflip_targets)}) via plugin…")
    if write_targets:
        print(f"  GDB direct-write injections ({len(write_targets)}) "
              f"with retry-verify…")

    results: list[InjectionResult] = []

    # Bit-flip path: use the existing campaign engine (pairwise hook active)
    if bitflip_targets:
        specs = [
            InjectionSpec(
                addr        = t["addr"],
                bit         = t["bit"],
                delay       = args.delay,
                symbol      = t["symbol"],
                byte_offset = t["byte_offset"],
                field_name  = t.get("field", ""),
            )
            for t in bitflip_targets
        ]
        bitflip_results = campaign.run_targets(specs)
        results.extend(bitflip_results)
        campaign.print_summary()

    # GDB write path: bypass plugin, write value with retry-verify
    if write_targets:
        if not _docker_mode or not GDB_HOST:
            print("  WARNING: GDB-write targets need Docker mode + GDB host — skipping")
        else:
            write_oracle = PtyOracle(_oracle_log)
            write_oracle.start()
            try:
                for i, t in enumerate(write_targets, 1):
                    is_last = (i == len(write_targets))
                    label = (f"{t['symbol']} :: {t['field']}" if t.get("field")
                             else (t.get("symbol") or f"0x{t.get('addr',0):08x}"))
                    print(f"\n[GDB-write {i}/{len(write_targets)}] {label}",
                          flush=True)

                    # Synthetic targets: dedicated handlers (no retry-verify race)
                    if t.get("synthetic") == "HLTH_PING_WARN":
                        time.sleep(2.0)   # let any in-flight ping settle
                        r = _run_hlth_ping_warn(
                            syms              = syms,
                            gdb_host          = GDB_HOST,
                            fi_sock           = SOCK_PATH,
                            oracle            = write_oracle,
                            liveness_timeout_s = 5.0,
                        )
                        print(f"  -> outcome={r.outcome}  evidence={r.evidence[:80]}",
                              flush=True)
                        if _pairwise_hook and r.outcome != "DETECTED":
                            hook_out = _pairwise_hook(r)
                            if hook_out and hook_out != "STOP":
                                r.outcome = hook_out
                        results.append(r)

                    elif t.get("synthetic") == "HLTH_PING_FATAL":
                        time.sleep(2.0)   # let any in-flight ping settle
                        r = _run_hlth_ping_fatal(
                            syms              = syms,
                            gdb_host          = GDB_HOST,
                            fi_sock           = SOCK_PATH,
                            oracle            = write_oracle,
                            liveness_timeout_s = 5.0,
                        )
                        print(f"  -> outcome={r.outcome}  evidence={r.evidence[:80]}",
                              flush=True)
                        results.append(r)

                    elif t.get("synthetic") == "MASKED_BENIGN":
                        time.sleep(2.0)
                        r = _run_masked_benign(
                            syms              = syms,
                            gdb_host          = GDB_HOST,
                            fi_sock           = SOCK_PATH,
                            oracle            = write_oracle,
                            liveness_timeout_s = 5.0,
                        )
                        print(f"  -> outcome={r.outcome}  evidence={r.evidence[:80]}",
                              flush=True)
                        if _pairwise_hook and r.outcome != "DETECTED":
                            hook_out = _pairwise_hook(r)
                            if hook_out and hook_out != "STOP":
                                r.outcome = hook_out
                        results.append(r)

                    elif t.get("synthetic") == "MASKED_HEARTBEAT":
                        time.sleep(2.0)
                        r = _run_masked_heartbeat(
                            syms              = syms,
                            gdb_host          = GDB_HOST,
                            fi_sock           = SOCK_PATH,
                            oracle            = write_oracle,
                            liveness_timeout_s = 5.0,
                        )
                        print(f"  -> outcome={r.outcome}  evidence={r.evidence[:80]}",
                              flush=True)
                        if _pairwise_hook and r.outcome != "DETECTED":
                            hook_out = _pairwise_hook(r)
                            if hook_out and hook_out != "STOP":
                                r.outcome = hook_out
                        results.append(r)

                    elif t.get("synthetic") == "MASKED_SILENT_HEALTH_DISABLE":
                        time.sleep(2.0)
                        r = _run_masked_silent_health_disable(
                            syms              = syms,
                            gdb_host          = GDB_HOST,
                            fi_sock           = SOCK_PATH,
                            oracle            = write_oracle,
                            liveness_timeout_s = 5.0,
                        )
                        print(f"  -> outcome={r.outcome}  evidence={r.evidence[:80]}",
                              flush=True)
                        if _pairwise_hook and r.outcome != "DETECTED":
                            hook_out = _pairwise_hook(r)
                            if hook_out and hook_out != "STOP":
                                r.outcome = hook_out
                        results.append(r)

                    else:
                        print(f"  addr=0x{t['addr']:08x}  write_value={t['write_value']}",
                              flush=True)
                        r = _run_gdb_write(
                            target               = t,
                            gdb_host             = GDB_HOST,
                            oracle               = write_oracle,
                            observation_window_s = _window,
                            liveness_timeout_s   = 5.0,
                        )
                        print(f"  -> outcome={r.outcome}  evidence={r.evidence[:80]}",
                              flush=True)
                        if _pairwise_hook and r.outcome != "DETECTED":
                            hook_out = _pairwise_hook(r)
                            if hook_out and hook_out != "STOP":
                                r.outcome = hook_out
                        results.append(r)

                    # Layer-5 integrity check (write-targets path)
                    # Bit-flip targets get this automatically inside SEUCampaign;
                    # write targets bypass that engine so we run the SAME check
                    # here using the SAME shared helper.  When drift is found we
                    # promote the outcome to MASKED_CRITICAL same semantics as
                    # SEUCampaign.run_targets does for bit-flip path.
                    if r.outcome == "MASKED" and cfg.critical_params:
                        try:
                            _gdb_inj_check = GdbMemWriter(host=GDB_HOST, port=1234)
                            diverged = check_critical_params(cfg.critical_params,
                                                             _gdb_inj_check)
                            if diverged:
                                name, exp, act = diverged[0]
                                extra = f" (+{len(diverged)-1} more)" if len(diverged) > 1 else ""
                                r.outcome = "MASKED_CRITICAL"
                                r.suspect_reason = (
                                    f"critical param diverged: {name} "
                                    f"expected={exp} got={act}{extra}"
                                )
                                print(f"  Layer-5: {len(diverged)} critical param(s) "
                                      f"diverged — first: {name} expected={exp} got={act} "
                                      f"→ outcome promoted to MASKED_CRITICAL",
                                      flush=True)
                            else:
                                print(f"  Layer-5: all {len(cfg.critical_params)} "
                                      f"critical params intact ✓", flush=True)
                        except Exception as _e:
                            print(f"  WARNING: Layer-5 integrity check failed ({_e})",
                                  flush=True)

                    # Push this write-target result into the campaign's internal
                    # results list AND the JSONL/DB record, so print_summary
                    # sees it alongside bit-flip results single unified report.
                    campaign._results.append(r)
                    campaign._append_result(r)

                    # Reset between injections same as --ci run_targets() 
                    # Each SEU must start from a clean CHESS state so results are
                    # independent.  Mirrors injector.py:1188-1261 exactly:
                    #   fast path  -> loadvm(snapshot) if available
                    #   slow path  -> system_reset + wait for CHESS boot
                    if not is_last:
                        _gdb_rst = GdbMemWriter(host=GDB_HOST, port=1234)
                        _snap = campaign.cfg.snapshot_name
                        if _snap:
                            print(f"  Restoring snapshot '{_snap}'…", flush=True)
                            _ok = _gdb_rst.loadvm(_snap)
                            print(f"  Snapshot {'restored' if _ok else 'FAILED'}",
                                  flush=True)
                            if NEST_URL:
                                try:
                                    from nest_client.client import NestClient
                                    with NestClient(url=NEST_URL) as _nc:
                                        _nc.send_command("M4B", "switch_back_to_a7a", "{}")
                                except Exception as _e:
                                    print(f"  WARNING: M4B reset failed ({_e})", flush=True)
                        else:
                            print("  system_reset (no snapshot)…", flush=True)
                            _gdb_rst.system_reset()
                        # Wait for sustained CHESS event flow (not just one event),
                        # so the CPU is firmly in CHESS user-context — not stuck
                        # in early init where BSS isn't mapped yet.
                        print("  Waiting for active CHESS beacon after reset…",
                              flush=True)
                        write_oracle.drain()
                        if wait_for_beacon(write_oracle, timeout_s=120.0):
                            print("  CHESS beacon active ✓", flush=True)
                        else:
                            print("  WARNING: beacon not advancing after reset (120s)",
                                  flush=True)
                        # Extra settle so the CPU has time to leave any
                        # transient kernel-context window between events.
                        time.sleep(3.0)
            finally:
                write_oracle.stop()

    # Unified 5-layer report same as --ci's path, via campaign.print_summary
    # All injections (bit-flip and write) now live in campaign._results, so this
    # single call produces the canonical 5-layer breakdown including CRASH /
    # DETECTED / MASKED (verified vs suspect) / PAIRWISE / GOLDEN.
    campaign.print_summary()

    if run_id:
        from nest_client.seu.result_db import SEUResultDB
        with SEUResultDB(SEU_DB) as db:
            db.print_masked_rates(run_id, filter_prefix="")
        print(f"\n  run_id: {run_id}")
