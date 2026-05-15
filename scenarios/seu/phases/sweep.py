"""Phase 2: automated ELF sweep."""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

from nest_client.seu.injector import CampaignConfig, SEUCampaign, InjectionSpec

from ..config import (
    ELF_PATH, SOCK_PATH, RESULTS,
    _docker_mode, PTY_LOG, GDB_HOST,
)
from ..helpers import print_banner


def print_elf_analysis(elf_path: Path, candidates_only: bool = True) -> None:
    """Print a compact ELF candidate summary before the sweep."""
    from nest_client.seu.elf_analyzer import summarise_candidates
    rows = summarise_candidates(elf_path, candidates_only=candidates_only)
    w = 70
    print("\n" + "─" * w)
    print(f"  ELF candidate symbols  ({len(rows)} total)")
    print("─" * w)
    print(f"  {'SYMBOL':<42} {'SECT':<5} {'SIZE':>7}")
    print(f"  {'──────':<42} {'────':<5} {'────':>7}")
    for r in rows:
        name = r["name"]
        if len(name) > 42:
            name = name[:39] + "…"
        print(f"  {name:<42} {r['section']:<5} {r['size']:>7,}")
    print("─" * w + "\n")


def run_automated_sweep(args) -> None:
    label = "Phase 2 (Automated Sweep)"
    if getattr(args, "random", False):
        label = (f"Phase 2 (Stratified Random Sweep  "
                 f"seed={args.seed}  n={args.max_targets})")
    print_banner(f"SEU Fault Injection {label}")

    if not ELF_PATH.exists():
        sys.exit(f"ERROR: ELF not found: {ELF_PATH}")

    print_elf_analysis(ELF_PATH, candidates_only=not args.all_symbols)

    cfg = CampaignConfig(
        socket_path             = SOCK_PATH,
        elf_path                = ELF_PATH,
        pty_log_path            = PTY_LOG,
        delay_insn              = args.delay,
        observation_window_s    = args.window,
        candidates_only         = not args.all_symbols,
        filter_re               = args.filter,
        results_path            = RESULTS,
        use_insn_count_liveness = _docker_mode,
        gdb_host                = GDB_HOST if _docker_mode else None,
        gdb_port                = 1234,
    )
    campaign = SEUCampaign(cfg)

    if getattr(args, "random", False):
        import random as _rnd
        from nest_client.seu.elf_analyzer import get_bituniform_sample

        rng    = _rnd.Random(args.seed)
        sample = get_bituniform_sample(
            ELF_PATH, n=args.max_targets, rng=rng,
            candidates_only=not args.all_symbols,
        )
        sym_counts = Counter(t["symbol"][:45] for t in sample)
        print(f"  Strategy : uniform across {len(sym_counts)} distinct symbols  "
              f"(seed={args.seed})")
        print(f"  Targets  : {len(sample)}\n")
        for sym, cnt in sorted(sym_counts.items()):
            print(f"    {cnt:2d}×  {sym}")
        print()
        specs   = [InjectionSpec(addr=t["addr"], bit=t["bit"], delay=args.delay)
                   for t in sample]
        results = campaign.run_targets(specs)
    else:
        results = campaign.run_sweep(max_targets=args.max_targets)

    campaign.print_summary()
    print(f"\nResults written to {RESULTS}")
    return results
