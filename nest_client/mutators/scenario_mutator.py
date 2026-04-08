from __future__ import annotations

import argparse
import importlib.util
import random
import sys
from pathlib import Path
from unittest.mock import patch

import nest_client
from nest_client import command, s
from nest_client.scenario import Scenario


class FuzzingTimeline:
    """Wrap timeline and inject fuzzer start/stop commands at random times."""

    def __init__(self, original_timeline, rng: random.Random):
        self._inner = original_timeline()
        self._fuzzer_ids = ["net_fuzzer", "mem_fuzzer", "io_fuzzer"]
        self._rng = rng

    def __enter__(self):
        self._inner.__enter__()
        return self

    def __setitem__(self, time, action):
        # Randomly inject start_fuzzer BEFORE this action.
        if self._rng.random() < 0.3:
            fid = self._rng.choice(self._fuzzer_ids)
            self._inner[time] = command("fuzzer", "start_fuzzer", {"id": fid})

        # Original action.
        self._inner[time] = action

        # Randomly inject stop_fuzzer AFTER this action.
        if self._rng.random() < 0.3:
            fid = self._rng.choice(self._fuzzer_ids)
            stop_time = time + self._rng.uniform(0.5, 2.0) * s
            self._inner[stop_time] = command("fuzzer", "stop_fuzzer", {"id": fid})

    def __exit__(self, *exc_info):
        return self._inner.__exit__(*exc_info)


def load_and_fuzz(script_path: str, scenario_name: str, seed: int | None = None) -> tuple[Scenario, int]:
    fuzz_seed = seed if seed is not None else random.randint(0, 99999)
    rng = random.Random(fuzz_seed)

    path = Path(script_path).resolve()
    spec = importlib.util.spec_from_file_location("scenario_module", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load scenario module from {path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules["scenario_module"] = module

    original_timeline = nest_client.timeline

    with (
        patch(
            "nest_client.timeline",
            lambda: FuzzingTimeline(original_timeline, rng),
        ),
        patch(
            "nest_client.sequence.timeline",
            lambda: FuzzingTimeline(original_timeline, rng),
        ),
    ):
        spec.loader.exec_module(module)

    scen = getattr(module, scenario_name, None)
    if not isinstance(scen, Scenario):
        raise TypeError(f"{scenario_name!r} is not a Scenario in {path}")

    return scen, fuzz_seed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("script", help="Path to the scenario .py file")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--scenario", default="demo", help="Scenario symbol name in the module")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    scenario, seed = load_and_fuzz(args.script, args.scenario, args.seed)

    print(f"[FUZZ] seed={seed} script={args.script} scenario={args.scenario}")
    for op in scenario.sequence.flatten():
        print(op)

    print(f"[FUZZ] built scenario={scenario.name} ops={len(scenario.sequence.flatten())}")


if __name__ == "__main__":
    main()
