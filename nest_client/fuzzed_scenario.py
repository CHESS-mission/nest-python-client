import argparse
import importlib.util
import random
import sys
from pathlib import Path
from unittest.mock import patch

import nest_client
from nest_client import command, s
from nest_client.scenario import Scenario

parser = argparse.ArgumentParser()
parser.add_argument("script", help="Path to the scenario .py file")
parser.add_argument("--seed", type=int, default=None)
parser.add_argument("--scenario", default="demo", help="Scenario symbol name in the module")
args = parser.parse_args()

FUZZ_SEED = args.seed if args.seed is not None else random.randint(0, 99999)
print(f"[FUZZ] seed={FUZZ_SEED} script={args.script} scenario={args.scenario}")
random.seed(FUZZ_SEED)

# Capture the real timeline before monkey-patching.
original_timeline = nest_client.timeline

class FuzzingTimeline:
    """Wrap the original timeline and inject fuzzer start/stop at random times."""

    def __init__(self):
        self._inner = original_timeline()
        self._fuzzer_ids = ["net_fuzzer", "mem_fuzzer", "io_fuzzer"]

    def __enter__(self):
        self._inner.__enter__()
        return self

    def __setitem__(self, time, action):
        # Randomly inject start_fuzzer BEFORE this action.
        if random.random() < 0.3:
            fid = random.choice(self._fuzzer_ids)
            self._inner[time] = command("fuzzer", "start_fuzzer", {"id": fid})

        # Original action.
        self._inner[time] = action

        # Randomly inject stop_fuzzer AFTER this action.
        if random.random() < 0.3:
            fid = random.choice(self._fuzzer_ids)
            stop_time = time + random.uniform(0.5, 2.0) * s
            self._inner[stop_time] = command("fuzzer", "stop_fuzzer", {"id": fid})

    def __exit__(self, *exc_info):
        return self._inner.__exit__(*exc_info)


def load_and_fuzz(script_path: str, scenario_name: str) -> Scenario:
    path = Path(script_path).resolve()
    spec = importlib.util.spec_from_file_location("scenario_module", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load scenario module from {path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules["scenario_module"] = module

    with patch("nest_client.timeline", FuzzingTimeline), patch("nest_client.sequence.timeline", FuzzingTimeline):
        spec.loader.exec_module(module)

    scen = getattr(module, scenario_name, None)
    if not isinstance(scen, Scenario):
        raise TypeError(f"{scenario_name!r} is not a Scenario in {path}")

    return scen


if __name__ == "__main__":
    scenario = load_and_fuzz(args.script, args.scenario)
    
    for i in scenario.sequence.flatten():
        print(i)

    print(f"[FUZZ] built scenario={scenario.name} ops={len(scenario.sequence.flatten())}")

