"""Phase: CI regression check — proportional, version-stable component sample."""

from __future__ import annotations

import sys
from collections import Counter

from nest_client.seu.elf_analyzer import get_stable_component_sample
from nest_client.seu.injector import CampaignConfig, SEUCampaign, InjectionSpec

from ..config import ELF_PATH, SOCK_PATH, SEU_DB, RESULTS, _docker_mode, PTY_LOG, CONSOLE_LOG, GDB_HOST
from ..helpers import print_banner


def run_ci(args) -> None:
    """
    CI regression check.

    Distributes --quota total injections across CHESS:: components proportionally
    by injectable bytes (larger components get more samples).  Targets are keyed
    by (symbol, field, bit_within_field) — stable across FS versions even when
    BSS addresses shift.  Exits 1 if any component masked rate increases by more
    than --threshold vs the baseline run.
    """
    total_quota = getattr(args, "quota",      60)
    seed        = getattr(args, "seed",       42)
    threshold   = getattr(args, "threshold",  0.10)
    baseline    = getattr(args, "baseline",   None)
    ci_filter   = getattr(args, "ci_filter",  "CHESS::")
    ci_exclude  = getattr(args, "ci_exclude", None)

    print_banner(f"SEU CI Regression Check  (quota={total_quota} total  seed={seed})")

    if not ELF_PATH.exists():
        sys.exit(f"ERROR: ELF not found: {ELF_PATH}")

    targets, comp_quotas = get_stable_component_sample(
        ELF_PATH,
        total_quota=total_quota,
        seed=seed,
        filter_prefix=ci_filter,
        exclude_re=ci_exclude,
    )

    if not targets:
        print(f"  No symbols found matching '{ci_filter}*'. Nothing to inject.")
        sys.exit(0)

    n_comps = len(comp_quotas)
    print(f"  Filter     : {ci_filter}*")
    print(f"  Components : {n_comps}")
    print(f"  Targets    : {len(targets)}  (proportional by injectable bytes)")
    print()
    for comp in sorted(comp_quotas):
        print(f"    {comp_quotas[comp]:3d}x  {ci_filter}{comp}")
    print()

    # Use the file-chardev console log when available (Docker mode).
    # This enables the PtyOracle to classify DETECTED outcomes via FPrime
    # EVENT: lines, not just MASKED/CRASH from the instruction-count oracle.
    _oracle_log = CONSOLE_LOG if CONSOLE_LOG is not None else PTY_LOG

    # oracle.classify() receives window * 0.5. Health monitoring fires after
    # ~3 rate-group cycles at 1 Hz, so the oracle needs at least 10s.
    _window = max(args.window, 20.0)

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
        gdb_host                = GDB_HOST if _docker_mode else None,
        gdb_port                = 1234,
    )
    campaign = SEUCampaign(cfg)
    run_id = campaign.start_db_run(
        topology="ci",
        notes=f"quota={total_quota} seed={seed} filter={ci_filter}",
    )

    specs = [
        InjectionSpec(
            addr=t["addr"], bit=t["bit"], delay=args.delay,
            symbol=t["symbol"], byte_offset=t["byte_offset"],
            field_name=t.get("field", ""),
        )
        for t in targets
    ]
    campaign.run_targets(specs)
    campaign.print_summary()

    if not run_id:
        print("  (no DB configured — skipping regression check)")
        return

    from nest_client.seu.result_db import SEUResultDB
    with SEUResultDB(SEU_DB) as db:
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
            print(f"\n  No baseline — results recorded as run_id: {run_id[:8]}")
            print("  Re-run with --baseline <run_id> to enable regression detection.")
