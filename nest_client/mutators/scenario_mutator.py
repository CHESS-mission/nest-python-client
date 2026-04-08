from __future__ import annotations

import argparse
import importlib.util
import random
import sys
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from nest_client.scenario import Scenario
from nest_client.sequence import command
from nest_client.time import s


@dataclass
class ScenarioMutationOptions:
    fuzzer_ids: list[str]
    start_probability: float = 0.3
    stop_probability: float = 0.3
    stop_delay_min_s: float = 0.5
    stop_delay_max_s: float = 2.0


DEFAULT_SCENARIO_MUTATION_OPTIONS = ScenarioMutationOptions(
    fuzzer_ids=["net_fuzzer", "mem_fuzzer", "io_fuzzer"],
)


class FuzzingTimeline:
    """Wrap timeline and inject fuzzer start/stop commands at random times."""

    def __init__(
        self,
        original_timeline,
        rng: random.Random,
        options: ScenarioMutationOptions,
    ):
        self._inner = original_timeline()
        self._rng = rng
        self._options = options

    def __enter__(self):
        self._inner.__enter__()
        return self

    def __setitem__(self, time, action):
        # Randomly inject start_fuzzer BEFORE this action.
        if self._rng.random() < self._options.start_probability:
            fid = self._rng.choice(self._options.fuzzer_ids)
            self._inner[time] = command("fuzzer", "start_fuzzer", {"id": fid})

        # Original action.
        self._inner[time] = action

        # Randomly inject stop_fuzzer AFTER this action.
        if self._rng.random() < self._options.stop_probability:
            fid = self._rng.choice(self._options.fuzzer_ids)
            stop_time = time + self._rng.uniform(
                self._options.stop_delay_min_s,
                self._options.stop_delay_max_s,
            ) * s
            self._inner[stop_time] = command("fuzzer", "stop_fuzzer", {"id": fid})

    def __exit__(self, *exc_info):
        return self._inner.__exit__(*exc_info)


def normalize_options(
    options: ScenarioMutationOptions | None,
) -> ScenarioMutationOptions:
    if options is None:
        return ScenarioMutationOptions(
            fuzzer_ids=list(DEFAULT_SCENARIO_MUTATION_OPTIONS.fuzzer_ids),
            start_probability=DEFAULT_SCENARIO_MUTATION_OPTIONS.start_probability,
            stop_probability=DEFAULT_SCENARIO_MUTATION_OPTIONS.stop_probability,
            stop_delay_min_s=DEFAULT_SCENARIO_MUTATION_OPTIONS.stop_delay_min_s,
            stop_delay_max_s=DEFAULT_SCENARIO_MUTATION_OPTIONS.stop_delay_max_s,
        )

    if not options.fuzzer_ids:
        raise ValueError("Scenario mutation requires at least one fuzzer ID")

    if not (0.0 <= options.start_probability <= 1.0):
        raise ValueError("start_probability must be in [0, 1]")
    if not (0.0 <= options.stop_probability <= 1.0):
        raise ValueError("stop_probability must be in [0, 1]")
    if options.stop_delay_min_s < 0:
        raise ValueError("stop_delay_min_s must be >= 0")
    if options.stop_delay_max_s < options.stop_delay_min_s:
        raise ValueError("stop_delay_max_s must be >= stop_delay_min_s")

    return options


def load_and_fuzz(
    script_path: str,
    scenario_name: str,
    seed: int | None = None,
    options: ScenarioMutationOptions | None = None,
) -> tuple[Scenario, int]:
    import nest_client as nest_client_pkg

    resolved_options = normalize_options(options)
    fuzz_seed = seed if seed is not None else random.randint(0, 99999)
    rng = random.Random(fuzz_seed)

    path = Path(script_path).resolve()
    spec = importlib.util.spec_from_file_location("scenario_module", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load scenario module from {path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules["scenario_module"] = module

    original_timeline = nest_client_pkg.timeline

    with (
        patch(
            "nest_client.timeline",
            lambda: FuzzingTimeline(original_timeline, rng, resolved_options),
        ),
        patch(
            "nest_client.sequence.timeline",
            lambda: FuzzingTimeline(original_timeline, rng, resolved_options),
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
    parser.add_argument("--fuzzer-id", action="append", default=None, help="Fuzzer ID (repeatable)")
    parser.add_argument("--start-probability", type=float, default=0.3)
    parser.add_argument("--stop-probability", type=float, default=0.3)
    parser.add_argument("--stop-delay-min", type=float, default=0.5)
    parser.add_argument("--stop-delay-max", type=float, default=2.0)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    options = ScenarioMutationOptions(
        fuzzer_ids=args.fuzzer_id or list(DEFAULT_SCENARIO_MUTATION_OPTIONS.fuzzer_ids),
        start_probability=args.start_probability,
        stop_probability=args.stop_probability,
        stop_delay_min_s=args.stop_delay_min,
        stop_delay_max_s=args.stop_delay_max,
    )

    scenario, seed = load_and_fuzz(args.script, args.scenario, args.seed, options)

    print(f"[FUZZ] seed={seed} script={args.script} scenario={args.scenario}")
    for op in scenario.sequence.flatten():
        print(op)

    print(f"[FUZZ] built scenario={scenario.name} ops={len(scenario.sequence.flatten())}")


if __name__ == "__main__":
    main()
