from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType
from typing import Any

import yaml

from nest_client.client import AsyncNestClient
from nest_client.scenario import Scenario, ValidationResult
from nest_client.sequence import Command, Event, SetEnv
from nest_client.time import s
from nest_client.mutators.scenario_mutator import (
    DEFAULT_SCENARIO_MUTATION_OPTIONS,
    ScenarioMutationOptions,
    load_and_fuzz,
)


@dataclass
class DescriptorScenarioConfig:
    script: Path
    name: str
    mutate: bool = True
    seed: int | None = None
    fuzzer_ids: list[str] | None = None
    start_probability: float = 0.3
    stop_probability: float = 0.3
    stop_delay_min_s: float = 0.5
    stop_delay_max_s: float = 2.0


@dataclass
class DescriptorTopologyConfig:
    mutate: bool = True
    seed: int = 0
    topology_file: Path | None = None
    persist_mutated: bool = False
    output_dir: Path | None = None


@dataclass
class DescriptorRunConfig:
    url: str
    artifacts_dir: Path


@dataclass
class MutationDescriptor:
    scenario: DescriptorScenarioConfig
    topology: DescriptorTopologyConfig
    run: DescriptorRunConfig


def _load_module_from_path(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("descriptor_scenario_module", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load scenario module from {path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules["descriptor_scenario_module"] = module
    spec.loader.exec_module(module)
    return module


def _load_scenario_without_mutation(script_path: Path, scenario_name: str) -> Scenario:
    module = _load_module_from_path(script_path)
    scenario_obj = getattr(module, scenario_name, None)
    if not isinstance(scenario_obj, Scenario):
        raise TypeError(f"{scenario_name!r} is not a Scenario in {script_path}")
    return scenario_obj


def _parse_descriptor(data: dict[str, Any], base_dir: Path, default_url: str) -> MutationDescriptor:
    scenario_data = data.get("scenario", {})
    if not isinstance(scenario_data, dict):
        raise ValueError("descriptor.scenario must be a mapping")

    script_value = scenario_data.get("script")
    if not isinstance(script_value, str) or not script_value.strip():
        raise ValueError("descriptor.scenario.script must be a non-empty string")

    scenario_script = (base_dir / script_value).resolve()
    scenario_name = scenario_data.get("name", "demo")
    if not isinstance(scenario_name, str) or not scenario_name.strip():
        raise ValueError("descriptor.scenario.name must be a non-empty string")

    scenario_mutate = bool(scenario_data.get("mutate", True))
    scenario_seed = scenario_data.get("seed")
    if scenario_seed is not None and not isinstance(scenario_seed, int):
        raise ValueError("descriptor.scenario.seed must be an integer or null")

    fuzzer_ids_value = scenario_data.get("fuzzer_ids")
    fuzzer_ids: list[str] | None = None
    if fuzzer_ids_value is not None:
        if not isinstance(fuzzer_ids_value, list) or not all(isinstance(v, str) for v in fuzzer_ids_value):
            raise ValueError("descriptor.scenario.fuzzer_ids must be a list of strings")
        fuzzer_ids = fuzzer_ids_value

    scenario_config = DescriptorScenarioConfig(
        script=scenario_script,
        name=scenario_name,
        mutate=scenario_mutate,
        seed=scenario_seed,
        fuzzer_ids=fuzzer_ids,
        start_probability=float(scenario_data.get("start_probability", 0.3)),
        stop_probability=float(scenario_data.get("stop_probability", 0.3)),
        stop_delay_min_s=float(scenario_data.get("stop_delay_min_s", 0.5)),
        stop_delay_max_s=float(scenario_data.get("stop_delay_max_s", 2.0)),
    )

    topology_data = data.get("topology", {})
    if not isinstance(topology_data, dict):
        raise ValueError("descriptor.topology must be a mapping")

    topology_file_value = topology_data.get("file")
    topology_file = None
    if topology_file_value is not None:
        if not isinstance(topology_file_value, str) or not topology_file_value.strip():
            raise ValueError("descriptor.topology.file must be a non-empty string")
        topology_file = (base_dir / topology_file_value).resolve()

    output_dir_value = topology_data.get("output_dir")
    output_dir = None
    if output_dir_value is not None:
        if not isinstance(output_dir_value, str) or not output_dir_value.strip():
            raise ValueError("descriptor.topology.output_dir must be a non-empty string")
        output_dir = (base_dir / output_dir_value).resolve()

    topology_seed = topology_data.get("seed", 0)
    if not isinstance(topology_seed, int):
        raise ValueError("descriptor.topology.seed must be an integer")

    topology_config = DescriptorTopologyConfig(
        mutate=bool(topology_data.get("mutate", True)),
        seed=topology_seed,
        topology_file=topology_file,
        persist_mutated=bool(topology_data.get("persist_mutated", False)),
        output_dir=output_dir,
    )

    run_data = data.get("run", {})
    if not isinstance(run_data, dict):
        raise ValueError("descriptor.run must be a mapping")

    run_url = run_data.get("url") or data.get("url") or default_url
    if not isinstance(run_url, str) or not run_url.strip():
        raise ValueError("descriptor.run.url must be a non-empty string")

    artifacts_dir_value = run_data.get("artifacts_dir", "mutations")
    if not isinstance(artifacts_dir_value, str) or not artifacts_dir_value.strip():
        raise ValueError("descriptor.run.artifacts_dir must be a non-empty string")
    artifacts_dir = (base_dir / artifacts_dir_value).resolve()

    return MutationDescriptor(
        scenario=scenario_config,
        topology=topology_config,
        run=DescriptorRunConfig(url=run_url, artifacts_dir=artifacts_dir),
    )


def load_descriptor(path: str | Path, default_url: str) -> MutationDescriptor:
    descriptor_path = Path(path).resolve()
    with descriptor_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    if not isinstance(data, dict):
        raise ValueError("Descriptor root must be a YAML mapping")

    return _parse_descriptor(data, descriptor_path.parent, default_url)


def _build_scenario(descriptor: MutationDescriptor) -> tuple[Scenario, int | None]:
    mutation_seed_used: int | None = None

    if descriptor.scenario.mutate:
        options = ScenarioMutationOptions(
            fuzzer_ids=(
                descriptor.scenario.fuzzer_ids
                if descriptor.scenario.fuzzer_ids is not None
                else list(DEFAULT_SCENARIO_MUTATION_OPTIONS.fuzzer_ids)
            ),
            start_probability=descriptor.scenario.start_probability,
            stop_probability=descriptor.scenario.stop_probability,
            stop_delay_min_s=descriptor.scenario.stop_delay_min_s,
            stop_delay_max_s=descriptor.scenario.stop_delay_max_s,
        )
        scenario, mutation_seed_used = load_and_fuzz(
            str(descriptor.scenario.script),
            descriptor.scenario.name,
            descriptor.scenario.seed,
            options,
        )
    else:
        scenario = _load_scenario_without_mutation(
            descriptor.scenario.script,
            descriptor.scenario.name,
        )

    if descriptor.topology.topology_file is not None:
        scenario.topology_file = descriptor.topology.topology_file

    scenario.mutate_topology = descriptor.topology.mutate
    scenario.mutation_seed = descriptor.topology.seed
    scenario.persist_mutated_topology = descriptor.topology.persist_mutated
    scenario.mutation_output_dir = descriptor.topology.output_dir

    return scenario, mutation_seed_used


def _new_run_artifact_dir(base_dir: Path, scenario_name: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = base_dir / f"{stamp}-{scenario_name}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def _serialize_item(item: Any) -> dict[str, Any]:
    if isinstance(item, Command):
        return {
            "kind": "command",
            "component": item.component,
            "name": item.name,
            "args": json.loads(item.args_json) if item.args_json else {},
        }

    if isinstance(item, Event):
        return {
            "kind": "event",
            "component": item.component,
            "name": item.name,
            "expect": item.expect,
            "within_s": item.within.as_unit(s) if item.within else None,
            "has_predicate": item.predicate is not None,
        }

    if isinstance(item, SetEnv):
        return {
            "kind": "set_env",
            "var": item.var,
            "type": str(item.type),
            "value": item.value,
            "lerp_over_s": item.lerp_over.as_unit(s) if item.lerp_over else None,
        }

    return {
        "kind": type(item).__name__,
        "repr": repr(item),
    }


def _write_run_artifacts(
    run_dir: Path,
    descriptor_path: Path,
    descriptor: MutationDescriptor,
    scenario: Scenario,
    scenario_seed: int | None,
) -> None:
    descriptor_summary = {
        "run": {
            "url": descriptor.run.url,
        },
        "scenario": {
            "script": str(descriptor.scenario.script),
            "name": descriptor.scenario.name,
            "mutate": descriptor.scenario.mutate,
            "seed": scenario_seed,
        },
        "topology": {
            "file": str(scenario.topology_file),
            "mutate": scenario.mutate_topology,
            "seed": scenario.mutation_seed,
            "persist_mutated": scenario.persist_mutated_topology,
            "output_dir": str(scenario.mutation_output_dir) if scenario.mutation_output_dir else None,
        },
    }
    (run_dir / "run.summary.yaml").write_text(
        yaml.safe_dump(descriptor_summary, sort_keys=False),
        encoding="utf-8",
    )

    ops = scenario.sequence.flatten()    

    (run_dir / "scenario.mutated.txt").write_text(
        "\n".join(repr(op) for op in ops),
        encoding="utf-8",
    )
    

def run_descriptor_file(
    descriptor_path: str | Path,
    default_url: str,
) -> tuple[Scenario, list[ValidationResult], str, int | None, Path]:
    resolved_descriptor_path = Path(descriptor_path).resolve()
    descriptor = load_descriptor(resolved_descriptor_path, default_url)
    scenario, scenario_seed = _build_scenario(descriptor)

    run_dir = _new_run_artifact_dir(descriptor.run.artifacts_dir, scenario.name)

    if scenario.mutate_topology:
        scenario.persist_mutated_topology = True
        scenario.mutation_output_dir = run_dir
        
    _write_run_artifacts(
        run_dir,
        resolved_descriptor_path,
        descriptor,
        scenario,
        scenario_seed,
    )

    client = AsyncNestClient(descriptor.run.url)
    results = scenario.run(client)

    return scenario, results, descriptor.run.url, scenario_seed, run_dir
