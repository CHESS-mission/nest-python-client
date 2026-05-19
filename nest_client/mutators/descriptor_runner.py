from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
import importlib.util
import json
import logging
from pathlib import Path
import random
import sys
from types import ModuleType
from typing import Any

import yaml

from nest_client.client import AsyncNestClient
from nest_client.remote.config import RemoteConfig, parse_remote_config
from nest_client.scenario import Scenario, ValidationResult
from nest_client.sequence import Command, Event, SetEnv
from nest_client.time import s
from nest_client.mutators.scenario_mutator import (
    FuzzerCommandTarget,
    ScenarioMutationOptions,
    load_and_fuzz,
)
from nest_client.mutators.topology_mutator import TopologyMutator


logger = logging.getLogger(__name__)

_LOG_FORMATTER = logging.Formatter(
    "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)


def _attach_run_log_handler(run_dir: Path) -> logging.FileHandler:
    """
    Attach a FileHandler to the root logger that writes to run_dir/run.log.
    A thread-ID filter is applied so parallel instances don't cross-contaminate.
    Returns the handler so the caller can remove it when the run finishes.
    """
    import threading
    tid = threading.get_ident()
    handler = logging.FileHandler(run_dir / "run.log", encoding="utf-8")
    handler.setFormatter(_LOG_FORMATTER)
    handler.addFilter(lambda record: threading.get_ident() == tid)
    logging.getLogger().addHandler(handler)
    return handler


def _detach_run_log_handler(handler: logging.FileHandler) -> None:
    logging.getLogger().removeHandler(handler)
    handler.close()


@dataclass
class ScenarioRegion:
    mode: str = "system"
    components: list[str] = field(default_factory=list)


@dataclass
class DescriptorScenarioConfig:
    script: Path
    name: str
    region: ScenarioRegion = field(default_factory=ScenarioRegion)
    start_probability: float = 0.3
    stop_probability: float = 0.3


@dataclass
class DescriptorRunConfig:
    url: str
    artifacts_dir: Path
    seed: int | None = None
    n_instances: int = 1


@dataclass
class DescriptorProtocolConfig:
    kind: str
    spec: Path


@dataclass
class DescriptorChipsFuzzConfig:
    mode: str = "random"
    fields: list[str] = field(default_factory=lambda: ["seq", "command", "payload"])
    payload_mode: str = "bitflip"
    flip_prob: float = 0.2
    max_flips: int = 2
    payload_flip_prob: float = 0.1
    max_payload_flips: int = 4
    max_payload_extend: int = 16


@dataclass
class DescriptorI2cPayloadFuzzConfig:
    mode: str = "random"


@dataclass
class DescriptorFuzzConfig:
    chips: DescriptorChipsFuzzConfig | None = None
    i2c_payload: DescriptorI2cPayloadFuzzConfig | None = None


@dataclass
class MutationDescriptor:
    scenario: DescriptorScenarioConfig
    run: DescriptorRunConfig
    protocol: DescriptorProtocolConfig | None = None
    fuzz: DescriptorFuzzConfig | None = None
    remote: RemoteConfig | None = None


def _parse_protocol_config(raw: Any, base_dir: Path) -> DescriptorProtocolConfig | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("descriptor.protocol must be a mapping")

    kind = raw.get("kind", "chips")
    if not isinstance(kind, str) or not kind.strip():
        raise ValueError("descriptor.protocol.kind must be a non-empty string")
    kind = kind.strip().lower()
    if kind != "chips":
        raise ValueError("descriptor.protocol.kind currently only supports 'chips'")

    spec_value = raw.get("spec")
    if not isinstance(spec_value, str) or not spec_value.strip():
        raise ValueError("descriptor.protocol.spec must be a non-empty string")
    spec = (base_dir / spec_value).resolve()
    if not spec.exists():
        raise ValueError(f"descriptor.protocol.spec not found: {spec}")

    return DescriptorProtocolConfig(kind=kind, spec=spec)


def _parse_fuzz_config(raw: Any) -> DescriptorFuzzConfig | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("descriptor.fuzz must be a mapping")

    i2c_payload_cfg = _parse_i2c_payload_fuzz_config(raw.get("i2c_payload"))

    chips_data = raw.get("chips")
    if chips_data is None:
        return DescriptorFuzzConfig(chips=None, i2c_payload=i2c_payload_cfg)
    if not isinstance(chips_data, dict):
        raise ValueError("descriptor.fuzz.chips must be a mapping")

    fields = chips_data.get("fields", ["seq", "command", "payload"])
    if not isinstance(fields, list) or not fields:
        raise ValueError("descriptor.fuzz.chips.fields must be a non-empty list")
    normalized_fields: list[str] = []
    for field_name in fields:
        if not isinstance(field_name, str) or not field_name.strip():
            raise ValueError("descriptor.fuzz.chips.fields entries must be non-empty strings")
        normalized = field_name.strip().lower()
        if normalized not in {"seq", "command", "payload", "is_response"}:
            raise ValueError(
                "descriptor.fuzz.chips.fields entries must be one of "
                "seq, command, payload, is_response"
            )
        normalized_fields.append(normalized)

    mode = str(chips_data.get("mode", "random")).strip().lower()
    if mode not in {"random", "typed"}:
        raise ValueError("descriptor.fuzz.chips.mode must be 'random' or 'typed'")

    payload_mode = str(chips_data.get("payload_mode", "bitflip")).strip().lower()
    if payload_mode not in {"bitflip", "random", "boundary", "truncate", "extend"}:
        raise ValueError(
            "descriptor.fuzz.chips.payload_mode must be one of "
            "bitflip, random, boundary, truncate, extend"
        )

    chips = DescriptorChipsFuzzConfig(
        mode=mode,
        fields=normalized_fields,
        payload_mode=payload_mode,
        flip_prob=float(chips_data.get("flip_prob", 0.2)),
        max_flips=int(chips_data.get("max_flips", 2)),
        payload_flip_prob=float(chips_data.get("payload_flip_prob", 0.1)),
        max_payload_flips=int(chips_data.get("max_payload_flips", 4)),
        max_payload_extend=int(chips_data.get("max_payload_extend", 16)),
    )
    return DescriptorFuzzConfig(chips=chips, i2c_payload=i2c_payload_cfg)


def _parse_i2c_payload_fuzz_config(raw: Any) -> DescriptorI2cPayloadFuzzConfig | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("descriptor.fuzz.i2c_payload must be a mapping")

    mode = str(raw.get("mode", "random")).strip().lower()
    if mode not in {"random", "boundary", "truncate", "extend"}:
        raise ValueError(
            "descriptor.fuzz.i2c_payload.mode must be one of random, boundary, truncate, extend"
        )
    return DescriptorI2cPayloadFuzzConfig(mode=mode)


def _normalize_chips_payload_types(raw: Any, *, context: str) -> dict[str, str]:
    if not isinstance(raw, dict):
        raise ValueError(f"{context} must be a mapping")

    normalized: dict[str, str] = {}
    for command, kind in raw.items():
        if not isinstance(command, str) or not isinstance(kind, str):
            raise ValueError(f"{context} entries must map strings to strings")
        key = command.strip()
        value = kind.strip().lower()
        if not key:
            raise ValueError(f"{context} keys must be non-empty")
        if value not in {"ascii", "u16_le", "u32_le", "bytes"}:
            raise ValueError(
                f"{context} payload types must be one of ascii, u16_le, u32_le, bytes"
            )
        normalized[key] = value

    return normalized


def _load_chips_protocol_spec(path: Path) -> dict[str, dict[str, str]]:
    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    if not isinstance(raw, dict):
        raise ValueError("CHIPS protocol spec must be a YAML mapping")

    # Root payload_types are accepted for backward compatibility but are no longer
    # used as an implicit fallback for all fuzzers.
    payload_types_root = raw.get("payload_types")
    if payload_types_root is not None:
        _normalize_chips_payload_types(
            payload_types_root,
            context="CHIPS protocol spec payload_types",
        )

    per_component_payload_types: dict[str, dict[str, str]] = {}

    components = raw.get("components", {})
    if components is None:
        components = {}
    if not isinstance(components, dict):
        raise ValueError("CHIPS protocol spec components must be a mapping")

    for component_name, component_data in components.items():
        if not isinstance(component_name, str) or not component_name.strip():
            raise ValueError("CHIPS protocol spec components keys must be non-empty strings")
        if not isinstance(component_data, dict):
            raise ValueError(
                "CHIPS protocol spec components entries must be mappings"
            )

        # Accept either:
        # components.<name>.payload_types: {...}
        # or shorthand components.<name>: {"0x10": "ascii", ...}
        if "payload_types" in component_data:
            payload_types_raw = component_data.get("payload_types")
        else:
            payload_types_raw = component_data

        per_component_payload_types[component_name.strip()] = _normalize_chips_payload_types(
            payload_types_raw,
            context=f"CHIPS protocol spec components.{component_name}.payload_types",
        )

    return per_component_payload_types


def _resolve_component_payload_types_for_fuzzer(
    protocol_payload_types: dict[str, dict[str, str]],
    fuzzer_name: str,
    connected_components: set[str],
) -> dict[str, str]:
    resolved: dict[str, str] = {}

    # A fuzzer-specific override can be provided directly under components.<fuzzer_name>.
    if fuzzer_name in protocol_payload_types:
        resolved.update(protocol_payload_types[fuzzer_name])

    # Merge connected component definitions (if present) so each fuzzer can use
    # schemas of the components it actually bridges.
    for component_name in sorted(connected_components):
        component_payload_types = protocol_payload_types.get(component_name)
        if component_payload_types is not None:
            resolved.update(component_payload_types)

    # Fallback heuristic from the auto-generated name pattern: Fuzzer_A_B(_...).
    if fuzzer_name.startswith("Fuzzer_"):
        for token in fuzzer_name.split("_")[1:]:
            component_payload_types = protocol_payload_types.get(token)
            if component_payload_types is not None:
                resolved.update(component_payload_types)

    return resolved


def _build_chips_strategy_config(
    descriptor: MutationDescriptor,
    *,
    payload_types: dict[str, str],
) -> dict[str, Any] | None:
    if descriptor.fuzz is None or descriptor.fuzz.chips is None:
        return None

    chips = descriptor.fuzz.chips
    return {
        "type": "chips_frame",
        "mode": chips.mode,
        "fields": chips.fields,
        "payload_mode": chips.payload_mode,
        "flip_prob": chips.flip_prob,
        "max_flips": chips.max_flips,
        "payload_flip_prob": chips.payload_flip_prob,
        "max_payload_flips": chips.max_payload_flips,
        "max_payload_extend": chips.max_payload_extend,
        "command_payload_types": payload_types,
    }


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

    if "mutate" in scenario_data:
        raise ValueError(
            "descriptor.scenario.mutate is no longer supported; "
            "run-mutator always mutates the scenario timeline"
        )

    if "seed" in scenario_data:
        raise ValueError(
            "descriptor.scenario.seed is no longer supported; "
            "use descriptor.run.seed for a shared mutation seed"
        )

    if "fuzzer_ids" in scenario_data:
        raise ValueError(
            "descriptor.scenario.fuzzer_ids is no longer supported; "
            "use descriptor.scenario.region instead"
        )

    scenario_region = _parse_scenario_region(scenario_data.get("region", "system"))

    scenario_config = DescriptorScenarioConfig(
        script=scenario_script,
        name=scenario_name,
        region=scenario_region,
        start_probability=float(scenario_data.get("start_probability", 0.3)),
        stop_probability=float(scenario_data.get("stop_probability", 0.3)),
    )

    if "topology" in data:
        raise ValueError(
            "descriptor.topology is no longer supported; topology path is taken from "
            "the scenario decorator, and mutated topology is always written under "
            "descriptor.run.artifacts_dir"
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

    run_seed = run_data.get("seed")
    if run_seed is not None and not isinstance(run_seed, int):
        raise ValueError("descriptor.run.seed must be an integer or null")

    n_instances = run_data.get("n_instances", 1)
    if not isinstance(n_instances, int) or n_instances < 1:
        raise ValueError("descriptor.run.n_instances must be a positive integer")

    protocol_config = _parse_protocol_config(data.get("protocol"), base_dir)
    fuzz_config = _parse_fuzz_config(data.get("fuzz"))

    if fuzz_config is not None and fuzz_config.chips is not None and fuzz_config.chips.mode == "typed":
        if protocol_config is None or protocol_config.kind != "chips":
            raise ValueError(
                "descriptor.fuzz.chips.mode='typed' requires descriptor.protocol.kind='chips'"
            )

    remote_config = parse_remote_config(data.get("remote"))

    return MutationDescriptor(
        scenario=scenario_config,
        run=DescriptorRunConfig(url=run_url, artifacts_dir=artifacts_dir, seed=run_seed, n_instances=n_instances),
        protocol=protocol_config,
        fuzz=fuzz_config,
        remote=remote_config,
    )


def load_descriptor(path: str | Path, default_url: str) -> MutationDescriptor:
    descriptor_path = Path(path).resolve()
    with descriptor_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    if not isinstance(data, dict):
        raise ValueError("Descriptor root must be a YAML mapping")

    return _parse_descriptor(data, descriptor_path.parent, default_url)


def _parse_scenario_region(value: Any) -> ScenarioRegion:
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            raise ValueError("descriptor.scenario.region must be non-empty")
        lowered = stripped.lower()
        if lowered in {"system", "all", "whole"}:
            return ScenarioRegion(mode="system")
        return ScenarioRegion(mode="components", components=[stripped])

    if isinstance(value, list):
        if not value:
            raise ValueError("descriptor.scenario.region list must include at least one component")
        if not all(isinstance(v, str) and v.strip() for v in value):
            raise ValueError("descriptor.scenario.region list entries must be non-empty strings")
        unique = sorted({v.strip() for v in value})
        return ScenarioRegion(mode="components", components=unique)

    raise ValueError(
        "descriptor.scenario.region must be either 'system', a component name, "
        "or a list of component names"
    )


def _extract_fuzzer_targets(
    topology: dict[str, Any],
    region: ScenarioRegion,
) -> tuple[list[FuzzerCommandTarget], dict[str, Any], dict[str, set[str]]]:
    components = topology.get("components", [])
    wires = topology.get("wires", [])

    if not isinstance(components, list):
        raise ValueError("Topology components must be a list")
    if not isinstance(wires, list):
        raise ValueError("Topology wires must be a list")

    fuzzer_names: set[str] = set()
    non_fuzzer_names: set[str] = set()
    groups_by_fuzzer: dict[str, set[str]] = {}

    for comp in components:
        if not isinstance(comp, dict):
            continue
        name = comp.get("name")
        if not isinstance(name, str):
            continue

        if comp.get("type") == "fuzzer":
            fuzzer_names.add(name)
            groups: set[str] = set()
            config = comp.get("config", {})
            if isinstance(config, dict):
                fuzzed_ports = config.get("fuzzed_ports", [])
                if isinstance(fuzzed_ports, list):
                    for entry in fuzzed_ports:
                        if not isinstance(entry, dict):
                            continue
                        group_name = entry.get("name")
                        if isinstance(group_name, str) and group_name:
                            groups.add(group_name)
            groups_by_fuzzer[name] = groups
        else:
            non_fuzzer_names.add(name)

    connected_components: dict[str, set[str]] = {name: set() for name in fuzzer_names}
    for wire in wires:
        if not isinstance(wire, list):
            continue

        endpoints: set[str] = set()
        for endpoint in wire:
            if not isinstance(endpoint, dict):
                continue
            component_name = endpoint.get("component")
            if isinstance(component_name, str):
                endpoints.add(component_name)

        wire_fuzzers = endpoints.intersection(fuzzer_names)
        if not wire_fuzzers:
            continue

        others = {name for name in endpoints if name not in fuzzer_names}
        for fuzzer_name in wire_fuzzers:
            connected_components[fuzzer_name].update(others)

    if region.mode == "system":
        selected_fuzzers = sorted(fuzzer_names)
    else:
        requested = set(region.components)
        unknown = sorted(requested - non_fuzzer_names)
        if unknown:
            raise ValueError(
                "descriptor.scenario.region includes unknown components: "
                f"{unknown}. Available components: {sorted(non_fuzzer_names)}"
            )
        selected_fuzzers = sorted(
            fuzzer_name
            for fuzzer_name in fuzzer_names
            if connected_components.get(fuzzer_name, set()).intersection(requested)
        )

    targets: list[FuzzerCommandTarget] = []
    for fuzzer_name in selected_fuzzers:
        for group_name in sorted(groups_by_fuzzer.get(fuzzer_name, set())):
            targets.append(FuzzerCommandTarget(component=fuzzer_name, group=group_name))

    if not targets:
        raise ValueError(
            "descriptor.scenario.region resolved to zero fuzzer targets. "
            f"Region mode={region.mode}, components={region.components}, "
            f"available fuzzer components={sorted(fuzzer_names)}"
        )

    summary = {
        "region": {
            "mode": region.mode,
            "components": region.components,
        },
        "available_components": sorted(non_fuzzer_names),
        "available_fuzzers": sorted(fuzzer_names),
        "resolved_fuzzers": selected_fuzzers,
        "resolved_fuzzer_connected_components": {
            name: sorted(connected_components.get(name, set()))
            for name in selected_fuzzers
        },
        "resolved_targets": [
            {"component": target.component, "group": target.group}
            for target in targets
        ],
    }
    selected_connected_components = {
        name: connected_components.get(name, set())
        for name in selected_fuzzers
    }
    return targets, summary, selected_connected_components


def _apply_strategy_to_targets(
    topology: dict[str, Any],
    targets: list[FuzzerCommandTarget],
    strategy_by_target: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    patched = deepcopy(topology)
    components = patched.get("components", [])
    if not isinstance(components, list):
        return patched

    by_component: dict[str, set[str]] = {}
    for target in targets:
        by_component.setdefault(target.component, set()).add(target.group)

    for comp in components:
        if not isinstance(comp, dict):
            continue
        comp_name = comp.get("name")
        if not isinstance(comp_name, str) or comp_name not in by_component:
            continue

        config = comp.get("config")
        if not isinstance(config, dict):
            continue

        fuzzed_ports = config.get("fuzzed_ports")
        if not isinstance(fuzzed_ports, list):
            continue

        target_groups = by_component[comp_name]
        for entry in fuzzed_ports:
            if not isinstance(entry, dict):
                continue
            group_name = entry.get("name")
            if not isinstance(group_name, str) or group_name not in target_groups:
                continue

            target_key = (comp_name, group_name)
            strategy = strategy_by_target.get(target_key)
            if strategy is None:
                continue

            for direction_key in ("comp_to_syst", "syst_to_comp"):
                direction_profile = entry.get(direction_key)
                if not isinstance(direction_profile, dict):
                    direction_profile = {}
                    entry[direction_key] = direction_profile
                direction_profile["enabled"] = False
                direction_profile["strategies"] = [deepcopy(strategy)]

    return patched


def _build_scenario(descriptor: MutationDescriptor) -> tuple[Scenario, int | None, dict[str, Any] | None]:
    mutation_seed_used = descriptor.run.seed
    if mutation_seed_used is None:
        mutation_seed_used = random.randint(0, 99999)

    selection_summary: dict[str, Any] | None = None

    base_scenario = _load_scenario_without_mutation(
        descriptor.scenario.script,
        descriptor.scenario.name,
    )

    topology_for_selection = base_scenario.topology_file
    topology_data = TopologyMutator(base_seed=mutation_seed_used).mutate_file(
        topology_for_selection
    )

    targets, selection_summary, selected_connected_components = _extract_fuzzer_targets(
        topology_data,
        descriptor.scenario.region,
    )

    strategy_by_target: dict[tuple[str, str], dict[str, Any]] = {}
    if descriptor.fuzz is not None and descriptor.fuzz.i2c_payload is not None:
        i2c_cfg = descriptor.fuzz.i2c_payload
        i2c_strategy = {"type": "i2c_payload", "mode": i2c_cfg.mode}
        for target in targets:
            strategy_by_target[(target.component, target.group)] = i2c_strategy

    if descriptor.fuzz is not None and descriptor.fuzz.chips is not None:
        protocol_payload_types: dict[str, dict[str, str]] = {}
        if descriptor.fuzz.chips.mode == "typed":
            if descriptor.protocol is None:
                raise ValueError(
                    "descriptor.fuzz.chips.mode='typed' requires descriptor.protocol with kind='chips'"
                )
            protocol_payload_types = _load_chips_protocol_spec(descriptor.protocol.spec)

        for target in targets:
            payload_types = {}
            if descriptor.fuzz.chips.mode == "typed":
                payload_types = _resolve_component_payload_types_for_fuzzer(
                    protocol_payload_types,
                    target.component,
                    selected_connected_components.get(target.component, set()),
                )
                if not payload_types:
                    connected = sorted(
                        selected_connected_components.get(target.component, set())
                    )
                    logger.warning(
                        "No CHIPS payload schema matched target %s.%s (connected_components=%s); "
                        "typed payload mutation falls back to random mode",
                        target.component,
                        target.group,
                        connected,
                    )

            strategy_config = _build_chips_strategy_config(
                descriptor,
                payload_types=payload_types,
            )
            if strategy_config is not None:
                strategy_by_target[(target.component, target.group)] = strategy_config

    if strategy_by_target:
        topology_data = _apply_strategy_to_targets(topology_data, targets, strategy_by_target)
        selection_summary["chips_strategy_by_target"] = {
            f"{component}.{group}": strategy
            for (component, group), strategy in sorted(strategy_by_target.items())
        }
        if descriptor.protocol is not None:
            selection_summary["protocol"] = {
                "kind": descriptor.protocol.kind,
                "spec": str(descriptor.protocol.spec),
            }

    options = ScenarioMutationOptions(
        targets=targets,
        start_probability=descriptor.scenario.start_probability,
        stop_probability=descriptor.scenario.stop_probability,
    )
    scenario, mutation_seed_used = load_and_fuzz(
        str(descriptor.scenario.script),
        descriptor.scenario.name,
        mutation_seed_used,
        options,
    )

    scenario.mutate_topology = True
    scenario.mutation_seed = mutation_seed_used
    scenario.persist_mutated_topology = True
    scenario.mutation_output_dir = None
    if strategy_by_target:
        scenario.topology_mutation_transform = lambda topology: _apply_strategy_to_targets(
            topology,
            targets,
            strategy_by_target,
        )

    if selection_summary is not None:
        selection_summary["topology_file"] = str(scenario.topology_file)
        selection_summary["selection_topology_mutated"] = True

    return scenario, mutation_seed_used, selection_summary


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
    selection_summary: dict[str, Any] | None,
) -> None:
    descriptor_summary = {
        "run": {
            "url": descriptor.run.url,
            "seed": scenario_seed,
        },
        "protocol": (
            {
                "kind": descriptor.protocol.kind,
                "spec": str(descriptor.protocol.spec),
            }
            if descriptor.protocol is not None
            else None
        ),
        "fuzz": (
            {
                **(
                    {
                        "chips": {
                            "mode": descriptor.fuzz.chips.mode,
                            "fields": descriptor.fuzz.chips.fields,
                            "payload_mode": descriptor.fuzz.chips.payload_mode,
                            "flip_prob": descriptor.fuzz.chips.flip_prob,
                            "max_flips": descriptor.fuzz.chips.max_flips,
                            "payload_flip_prob": descriptor.fuzz.chips.payload_flip_prob,
                            "max_payload_flips": descriptor.fuzz.chips.max_payload_flips,
                            "max_payload_extend": descriptor.fuzz.chips.max_payload_extend,
                        }
                    }
                    if descriptor.fuzz.chips is not None
                    else {}
                ),
                **(
                    {"i2c_payload": {"mode": descriptor.fuzz.i2c_payload.mode}}
                    if descriptor.fuzz.i2c_payload is not None
                    else {}
                ),
            }
            if descriptor.fuzz is not None
            else None
        ),
        "scenario": {
            "script": str(descriptor.scenario.script),
            "name": descriptor.scenario.name,
            "seed": scenario_seed,
            "region": {
                "mode": descriptor.scenario.region.mode,
                "components": descriptor.scenario.region.components,
            },
            "resolved_fuzzer_targets": selection_summary,
        },
        "topology": {
            "file": str(scenario.topology_file),
            "seed": scenario.mutation_seed,
            "persist_mutated": True,
            "output_dir": str(run_dir),
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
    

def _write_validation_report(
    run_dir: Path,
    scenario: Scenario,
    results: list[ValidationResult],
) -> None:
    REPORT_WIDTH = 80
    lines: list[str] = []
    lines.append(f"Scenario: {scenario.name}")
    lines.append("")

    total_pass = 0
    from collections import defaultdict as _defaultdict
    scope_groups: dict = _defaultdict(list)

    for result in results:
        path = tuple(scope.label or "" for scope in result.op.scope_stack)
        scope_groups[path].append(result)

    for path in sorted(scope_groups.keys()):
        scope_results = scope_groups[path]
        scope = scope_results[0].op.scope_stack[-1]
        path_string = " / ".join(label for label in path if label != "")

        lines.append("─" * REPORT_WIDTH)
        scope_window = f"[{scope.start.as_unit(s)}s -> {scope.end.as_unit(s)}s]"
        lines.append(f"{path_string:<{REPORT_WIDTH - len(scope_window) - 1}} {scope_window}")
        lines.append("─" * REPORT_WIDTH)
        lines.append("")

        for result in scope_results:
            event = result.op.item
            assert isinstance(event, Event)
            expect = "EXPECT" if event.expect else "FORBID"
            symbol = "OK" if result.success else "FAILED"
            window_start = result.op.offset.as_unit(s)
            window_end = (
                result.op.offset + event.within if event.within else scope.end
            ).as_unit(s)
            lines.append(f"  [{symbol}] {expect} {event.component}.{event.name} [{window_start}s -> {window_end}s]")
            total_pass += result.success

        lines.append("")

    total_fail = len(results) - total_pass
    lines.append("─" * REPORT_WIDTH)
    lines.append("Summary:")
    lines.append(f"  {total_pass} passed")
    lines.append(f"  {total_fail} failed")
    lines.append("")
    lines.append("Result: " + ("SUCCESS" if total_fail == 0 else "FAILED"))

    (run_dir / "report.txt").write_text("\n".join(lines), encoding="utf-8")


def run_descriptor_file(
    descriptor_path: str | Path,
    default_url: str,
    dashboard=None,
) -> tuple[Scenario, list[ValidationResult], str, int | None, Path]:
    resolved_descriptor_path = Path(descriptor_path).resolve()
    descriptor = load_descriptor(resolved_descriptor_path, default_url)
    scenario, scenario_seed, selection_summary = _build_scenario(descriptor)

    run_dir = _new_run_artifact_dir(descriptor.run.artifacts_dir, scenario.name)

    log_handler = _attach_run_log_handler(run_dir)
    server_log = open(run_dir / "server.log", "w", encoding="utf-8")
    try:
        scenario.persist_mutated_topology = True
        scenario.mutation_output_dir = run_dir

        def _on_server_msg(msg: dict) -> None:
            server_log.write(json.dumps(msg) + "\n")
            server_log.flush()
            if dashboard is not None:
                dashboard.on_server_msg(0, msg)

        scenario.on_server_message = _on_server_msg

        _write_run_artifacts(
            run_dir,
            resolved_descriptor_path,
            descriptor,
            scenario,
            scenario_seed,
            selection_summary,
        )

        if dashboard is not None:
            from nest_client.remote.dashboard import Phase
            dashboard.update(0, Phase.RUNNING)

        client = AsyncNestClient(descriptor.run.url)
        try:
            results = scenario.run(client)
        except Exception as exc:
            if dashboard is not None:
                from nest_client.remote.dashboard import Phase
                dashboard.update(0, Phase.FAILED, error_msg=str(exc))
            raise

        if dashboard is not None:
            from nest_client.remote.dashboard import Phase
            n_pass = sum(r.success for r in results)
            n_fail = len(results) - n_pass
            dashboard.update(0, Phase.DONE, passed=n_pass, failed=n_fail)
    finally:
        _detach_run_log_handler(log_handler)
        server_log.close()

    return scenario, results, descriptor.run.url, scenario_seed, run_dir
