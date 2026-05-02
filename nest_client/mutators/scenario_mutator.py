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


@dataclass(frozen=True)
class FuzzerCommandTarget:
    component: str
    group: str


@dataclass
class ScenarioMutationOptions:
    targets: list[FuzzerCommandTarget]
    start_probability: float = 0.3
    stop_probability: float = 0.3


DEFAULT_SCENARIO_MUTATION_OPTIONS = ScenarioMutationOptions(
    targets=[
        FuzzerCommandTarget(component="net_fuzzer", group="net_fuzzer"),
        FuzzerCommandTarget(component="mem_fuzzer", group="mem_fuzzer"),
        FuzzerCommandTarget(component="io_fuzzer", group="io_fuzzer"),
    ],
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
        self._active_targets: set[FuzzerCommandTarget] = set()

    def __enter__(self):
        self._inner.__enter__()
        return self

    def __setitem__(self, time, action):
        # Randomly enable a fuzz group BEFORE this action.
        if self._rng.random() < self._options.start_probability:
            start_candidates = [
                target
                for target in self._options.targets
                if target not in self._active_targets
            ]
            if start_candidates:
                target = self._rng.choice(start_candidates)
                self._inner[time] = command(
                    target.component,
                    "set_enabled",
                    {
                        "group": target.group,
                        "direction": "both",
                        "enabled": True,
                    },
                )
                self._active_targets.add(target)

        # Original action.
        self._inner[time] = action

        # Randomly disable a fuzz group AFTER this action.
        if self._rng.random() < self._options.stop_probability:
            stop_candidates = list(self._active_targets)
            if stop_candidates:
                target = self._rng.choice(stop_candidates)
                self._inner[time] = command(
                    target.component,
                    "set_enabled",
                    {
                        "group": target.group,
                        "direction": "both",
                        "enabled": False,
                    },
                )
                self._active_targets.discard(target)

    def __exit__(self, *exc_info):
        return self._inner.__exit__(*exc_info)


def normalize_options(
    options: ScenarioMutationOptions | None,
) -> ScenarioMutationOptions:
    if options is None:
        return ScenarioMutationOptions(
            targets=list(DEFAULT_SCENARIO_MUTATION_OPTIONS.targets),
            start_probability=DEFAULT_SCENARIO_MUTATION_OPTIONS.start_probability,
            stop_probability=DEFAULT_SCENARIO_MUTATION_OPTIONS.stop_probability,
        )

    if not options.targets:
        raise ValueError("Scenario mutation requires at least one fuzzer target")

    if not (0.0 <= options.start_probability <= 1.0):
        raise ValueError("start_probability must be in [0, 1]")
    if not (0.0 <= options.stop_probability <= 1.0):
        raise ValueError("stop_probability must be in [0, 1]")

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
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    options = ScenarioMutationOptions(
        targets=(
            [FuzzerCommandTarget(component=fid, group=fid) for fid in args.fuzzer_id]
            if args.fuzzer_id
            else list(DEFAULT_SCENARIO_MUTATION_OPTIONS.targets)
        ),
        start_probability=args.start_probability,
        stop_probability=args.stop_probability,
    )

    scenario, seed = load_and_fuzz(args.script, args.scenario, args.seed, options)

    print(f"[FUZZ] seed={seed} script={args.script} scenario={args.scenario}")
    for op in scenario.sequence.flatten():
        print(op)

    print(f"[FUZZ] built scenario={scenario.name} ops={len(scenario.sequence.flatten())}")


if __name__ == "__main__":
    main()
