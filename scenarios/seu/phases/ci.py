"""Phase: CI regression check — proportional, version-stable component sample."""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

from nest_client.seu.elf_analyzer import (get_stable_component_sample, get_code_sample,
                                          analyze_cached as analyze)
from nest_client.seu.injector import CampaignConfig, SEUCampaign, InjectionSpec, GdbMemWriter
from nest_client.seu.critical_params import build_health_critical_params

from ..config import ELF_PATH, SOCK_PATH, SEU_DB, RESULTS, _docker_mode, PTY_LOG, CONSOLE_LOG, GDB_HOST, NEST_URL
from ..helpers import print_banner, ensure_beacon
from ..pairwise import PairwiseHook


def run_ci(args) -> None:
    """
    CI regression check.

    Distributes --quota total injections across CHESS:: components proportionally
    by injectable bytes (larger components get more samples).  Targets are keyed
    by (symbol, field, bit_within_field) — stable across FS versions even when
    BSS addresses shift.  Exits 1 if any component masked rate increases by more
    than --threshold vs the baseline run.
    """
    total_quota   = getattr(args, "quota",         60)
    per_component = getattr(args, "per_component", None)
    seed          = getattr(args, "seed",          42)
    threshold     = getattr(args, "threshold",     0.10)
    baseline      = getattr(args, "baseline",      None)
    ci_filter     = getattr(args, "ci_filter",     "CHESS::")
    ci_exclude    = getattr(args, "ci_exclude",    None)

    # --sweep routes through the same pipeline as --ci, but with the symbol
    # filter cleared so every .bss/.data symbol is sampled proportionally to
    # its size -- a radiation-like uniform-per-byte distribution rather than
    # the namespace-scoped sample that --ci uses.  --per-component is forbidden
    # in sweep mode (the whole point of sweep is byte-weighted sampling).
    sweep_mode = getattr(args, "sweep", False)
    code_mode  = getattr(args, "code", False)
    if sweep_mode and per_component:
        sys.exit("ERROR: --per-component cannot be combined with --sweep "
                 "(sweep is radiation-like proportional sampling by design)")

    # --code samples code/rodata of the running release ELF, not .bss/.data
    # state.  Sections come from --sections; default text,rodata.
    _code_sections = tuple(
        "." + s.strip().lstrip(".")
        for s in (getattr(args, "sections", None) or "text,rodata").split(",")
        if s.strip()
    )
    _vtables_only = getattr(args, "vtables", False)
    _code_filter  = getattr(args, "code_filter", None)

    if code_mode:
        if _vtables_only:
            _what = "vtables only"
        elif _code_filter:
            _what = f"symbols matching /{_code_filter}/"
        else:
            _what = ",".join(_code_sections)
        print_banner(f"SEU Code/Rodata Sweep  "
                     f"(per byte over {_what}  quota={total_quota}  seed={seed})")
    elif sweep_mode:
        ci_filter  = ""
        ci_exclude = None
        print_banner(f"SEU Radiation-Like Sweep  "
                     f"(all regions .bss/.data/.text/.rodata  quota={total_quota}  seed={seed})")
    elif per_component:
        print_banner(f"SEU CI Regression Check  "
                     f"(per-component={per_component}  seed={seed})")
    else:
        print_banner(f"SEU CI Regression Check  (quota={total_quota} total  seed={seed})")

    if not ELF_PATH.exists():
        sys.exit(f"ERROR: ELF not found: {ELF_PATH}")

    # Optional stable (release) ELF what's actually running in QEMU.
    # When present, get_stable_component_sample uses it for runtime BSS
    # addresses, while keeping debug ELF's DWARF for field/size info.
    # Without it, every injection lands at debug-ELF addresses which can
    # differ wildly from runtime (debug build has different .text size ->
    # different BSS offsets) and the campaign reports misleading 100% MASKED.
    import os as _os
    _stable_elf_env = _os.environ.get("CHESS_STABLE_ELF_PATH")
    _stable_elf_path = (
        Path(_stable_elf_env) if _stable_elf_env and Path(_stable_elf_env).exists()
        else None
    )

    # --vtable-skip controls how many leading bytes of each component symbol
    # are excluded from sampling.  Default 64 keeps C++ vtable pointers and
    # port-connection fields out of the random sample (they'd dominate with
    # near-guaranteed CRASH outcomes).  Setting to 0 includes those targets
    # — recommended for radiation-realistic sweeps where CRASH outcomes
    # should appear in proportion to their physical footprint.
    _vtable_skip = getattr(args, "vtable_skip", 64)

    if code_mode:
        # Code/rodata SEU samples the running (release) ELF directly - its
        # .symtab is intact, so addresses and names are exact (no remap).
        import random as _random
        from collections import Counter as _Counter
        _code_elf = _stable_elf_path or ELF_PATH
        targets = get_code_sample(
            _code_elf, total_quota, _random.Random(seed),
            sections=_code_sections, vtables_only=_vtables_only,
            name_re=_code_filter, max_offset=getattr(args, "code_prologue", None),
        )
        ci_filter = ""
        comp_quotas = dict(_Counter(t["section"] for t in targets))
        _dist_desc = ("vtables only" if _vtables_only
                      else f"matching /{_code_filter}/" if _code_filter
                      else "uniform per byte over code/rodata")
        _flt_disp = f"<{','.join(_code_sections)} of {_code_elf.name}>"
    elif sweep_mode:
        # Radiation-like sweep across ALL allocatable regions: .bss/.data
        # (state) AND .text/.rodata (code).  Quota is split between the data and
        # code samplers in proportion to each region's byte size, so .text (the
        # largest region) gets the most samples -- matching the physical SEU
        # cross-section.  Both feed the same engine/classification as --ci.
        import random as _random
        from collections import Counter as _Counter
        from elftools.elf.elffile import ELFFile as _ELFFile
        _sweep_elf = _stable_elf_path or ELF_PATH
        _rsz = {}
        with open(_sweep_elf, "rb") as _f:
            _ef = _ELFFile(_f)
            for _sn in (".text", ".rodata", ".bss", ".data"):
                _sec = _ef.get_section_by_name(_sn)
                _rsz[_sn] = _sec["sh_size"] if _sec else 0
        _code_bytes = _rsz[".text"] + _rsz[".rodata"]
        _data_bytes = _rsz[".bss"] + _rsz[".data"]
        _tot_bytes  = (_code_bytes + _data_bytes) or 1
        _code_q = round(total_quota * _code_bytes / _tot_bytes)
        _data_q = total_quota - _code_q
        # Data portion: all .bss/.data symbols (filter cleared for sweep).
        if _data_q > 0:
            targets, comp_quotas = get_stable_component_sample(
                ELF_PATH, total_quota=_data_q, seed=seed,
                filter_prefix="", exclude_re=None,
                stable_elf_path=_stable_elf_path, vtable_skip=_vtable_skip,
                per_component_quota=per_component,
            )
            targets = list(targets)
        else:
            targets, comp_quotas = [], {}
        # Code portion: .text + .rodata of the running (release) ELF.
        if _code_q > 0:
            _code_targets = get_code_sample(
                _sweep_elf, _code_q, _random.Random(seed),
                sections=(".text", ".rodata"),
            )
            targets += _code_targets
            for _t in _code_targets:
                comp_quotas[_t["section"]] = comp_quotas.get(_t["section"], 0) + 1
        ci_filter = ""
        _dist_desc = (f"all regions, size-proportional: {_data_q} data "
                      f"(.bss/.data) + {_code_q} code (.text/.rodata)")
        _flt_disp = f"<all .bss/.data/.text/.rodata of {_sweep_elf.name}>"
    else:
        targets, comp_quotas = get_stable_component_sample(
            ELF_PATH,
            total_quota=total_quota,
            seed=seed,
            filter_prefix=ci_filter,
            exclude_re=ci_exclude,
            stable_elf_path=_stable_elf_path,
            vtable_skip=_vtable_skip,
            per_component_quota=per_component,
        )
        _dist_desc = (f"uniform per component"
                      if per_component else "proportional by injectable bytes")
        _flt_disp = f"{ci_filter}*" if ci_filter else "<all .bss/.data symbols (sweep mode)>"

    if not targets:
        print("  No targets produced. Nothing to inject.")
        sys.exit(0)

    n_comps = len(comp_quotas)
    print(f"  Filter     : {_flt_disp}")
    print(f"  {'Sections' if code_mode else 'Components'} : {n_comps}")
    print(f"  Targets    : {len(targets)}  ({_dist_desc})")
    print()
    for comp in sorted(comp_quotas):
        # comp is normally the suffix after ci_filter, but the fully-qualified
        # fallback (and code-mode section names) already carry the full label.
        _label = comp if comp.startswith(ci_filter) else f"{ci_filter}{comp}"
        print(f"    {comp_quotas[comp]:3d}x  {_label}")
    print()

    # Use the file-chardev console log when available (Docker mode).
    # This enables the PtyOracle to classify DETECTED outcomes via FPrime
    # EVENT: lines, not just MASKED/CRASH from the instruction-count oracle.
    _oracle_log = CONSOLE_LOG if CONSOLE_LOG is not None else PTY_LOG

    # oracle.classify() receives window * 0.5. Health monitoring fires after
    # ~3 rate-group cycles at 1 Hz, so the oracle needs at least 10s.
    _window = max(args.window, 20.0)

    # Build the pairwise hook so the CI fails immediately when an injection
    # produces an INCONSISTENT (obc, ea) pair — not just a masked rate regression.
    syms = analyze(ELF_PATH)
    _ea_sym  = next((s for s in syms if "eventAction"       in s.name and s.section == ".bss"), None)
    _obc_sym = next((s for s in syms if "obcSensorsManager" in s.name and s.section == ".bss"), None)
    _pairwise_hook = None
    if _ea_sym and _obc_sym:
        # Assume OBC starts in NOMINAL(4) during CI — avoids a probe campaign.
        # Override with actual OBC state if probing is desired.
        _OBC_NOMINAL = 4
        _pairwise_hook = PairwiseHook(
            ea_base_addr  = _ea_sym.address,
            obc_base_addr = _obc_sym.address,
            obc_state     = _OBC_NOMINAL,
            stop_on_first = True,   # cut CI immediately on first violation
        )
        print(f"  Pairwise hook: EA @ 0x{_ea_sym.address:08x} "
              f"OBC @ 0x{_obc_sym.address:08x} (assumed NOMINAL)")
    else:
        print("  WARNING: pairwise hook skipped — EA or OBC symbol not found")

    cfg = CampaignConfig(
        socket_path             = SOCK_PATH,
        elf_path                = ELF_PATH,
        pty_log_path            = _oracle_log,
        delay_insn              = args.delay,
        observation_window_s    = _window,
        candidates_only         = True,
        results_path            = RESULTS,
        db_path                 = SEU_DB,
        use_insn_count_liveness = False,   # always use event oracle for DETECTED
        liveness_timeout_s      = 5.0,
        gdb_host                = GDB_HOST if _docker_mode else None,
        gdb_port                = 1234,
        nest_url                = NEST_URL if _docker_mode else None,
        classify_hook           = _pairwise_hook,
        # critical_params is built below, after the snapshot is taken — same
        # shared helper that --ci-debug uses, same campaign-engine integration.
        critical_params         = None,
    )
    campaign = SEUCampaign(cfg)
    run_id = campaign.start_db_run(
        topology="ci",
        notes=f"quota={total_quota} seed={seed} filter={ci_filter}",
    )

    if _docker_mode:
        campaign.setup_snapshot("chess_ready")

    # Layer-5 critical-params build (shared with --ci-debug)
    if _docker_mode and GDB_HOST:
        from nest_client.seu.injector import PtyOracle, GdbMemWriter as _GdbW
        _oracle_log_for_wait = CONSOLE_LOG if CONSOLE_LOG is not None else PTY_LOG
        _wait_oracle = PtyOracle(_oracle_log_for_wait)
        _wait_oracle.start()
        try:
            print("  Ensuring active CHESS beacon before Layer-5 build…", flush=True)
            if ensure_beacon(_wait_oracle, GDB_HOST):
                print("  CHESS beacon active ✓", flush=True)
            else:
                print("  WARNING: beacon not advancing even after reset — "
                      "Layer-5 may be skipped", flush=True)
        finally:
            _wait_oracle.stop()

        try:
            _gdb_boot = _GdbW(host=GDB_HOST, port=1234)
            cfg.critical_params = build_health_critical_params(syms, _gdb_boot)
            if cfg.critical_params:
                print(f"  Registered {len(cfg.critical_params)} critical params for "
                      f"Layer-5 GOLDEN integrity check", flush=True)
        except Exception as _e:
            print(f"  WARNING: critical-params build failed ({_e})", flush=True)

    specs = [
        InjectionSpec(
            addr=t["addr"], bit=t["bit"], delay=args.delay,
            symbol=t["symbol"], byte_offset=t["byte_offset"],
            field_name=t.get("field", ""), section=t.get("section", ""),
        )
        for t in targets
    ]

    if getattr(args, "crash_probe", False) and not code_mode:
        _probe_elf = _stable_elf_path or ELF_PATH
        _cands = [s for s in analyze(_probe_elf)
                  if s.demangled.startswith(ci_filter)
                  and s.section == ".bss" and s.size >= 4]
        # main object = least-nested demangled name under the filter
        _cands.sort(key=lambda s: (len(s.demangled), s.demangled))
        if _cands:
            _base = _cands[0].address
            specs.insert(0, InjectionSpec(
                addr=_base + 3, bit=7, delay=args.delay,
                symbol=f"{_cands[0].demangled} (vtable ptr MSB - crash-probe)",
                byte_offset=3, field_name="vtable", section=".bss",
            ))
            print(f"  Crash-probe: {_cands[0].demangled} vtable ptr @ "
                  f"0x{_base:08x} (flip byte3 bit7 -> unmapped dispatch -> CRASH)",
                  flush=True)
        else:
            print(f"  WARNING: --crash-probe found no .bss object matching "
                  f"'{ci_filter}'; skipping probe", flush=True)

    if getattr(args, "batch", False):
        campaign.run_batch_sweep(
            specs=specs,
            init_batch=getattr(args, "batch_init", 2),
            max_batch=getattr(args, "batch_max", 16),
            grow=getattr(args, "batch_grow", 2),
            reproduce_k=getattr(args, "reproduce", 1),
        )
    else:
        campaign.run_targets(specs)
    campaign.print_summary()

    # Pairwise gate: fail immediately if any injection produced INCONSISTENT.
    # This check runs BEFORE the masked-rate regression so a pairwise violation
    # is always exposed even when the masked rate looks unchanged.
    if _pairwise_hook:
        _pairwise_hook.fail_if_inconsistent(label="CI pairwise invariant")

    if not run_id:
        print("  (no DB configured — skipping regression check)")
        return

    from nest_client.seu.result_db import SEUResultDB
    with SEUResultDB(SEU_DB) as db:
        # No explicit --baseline: auto-compare against the most recent prior
        # run built from the same binary, so every run produces a regression
        # report against the previous entry without manual baseline promotion.
        if not baseline:
            auto = db.previous_run(run_id, same_binary=True)
            if auto:
                baseline = auto
                print(f"  Auto-baseline: comparing against previous run "
                      f"{baseline[:8]} (same binary)")

        db.print_masked_rates(run_id, compare_run_id=baseline, filter_prefix=ci_filter)

        if baseline:
            rates_now  = db.masked_rate_by_component(run_id,  ci_filter)
            rates_base = db.masked_rate_by_component(baseline, ci_filter)
            regressions = [
                (sym, rates_base[sym]["masked_rate"], r["masked_rate"])
                for sym, r in rates_now.items()
                if sym in rates_base
                and (r["masked_rate"] - rates_base[sym]["masked_rate"]) > threshold
            ]
            if regressions:
                print(f"\n  CI FAILED — {len(regressions)} regression(s) exceed "
                      f"+{threshold*100:.0f}% threshold:")
                for sym, base, now in sorted(regressions, key=lambda x: -(x[2] - x[1])):
                    comp = sym.split("::")[-1] if "::" in sym else sym
                    print(f"    {comp}: {base*100:.1f}% -> {now*100:.1f}%  "
                          f"(+{(now-base)*100:.1f}%)")
                print(f"\n  run_id: {run_id}")
                sys.exit(1)
            else:
                print(f"\n  CI PASSED — all components within +{threshold*100:.0f}%.")
        else:
            print(f"\n  No prior run for this binary — results recorded as run_id: {run_id[:8]}")
            print("  The next run will auto-compare against this one.")
