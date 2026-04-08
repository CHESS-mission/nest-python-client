from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


Endpoint = dict[str, Any]
Connection = tuple[Endpoint, Endpoint]


@dataclass
class PairFuzzerSpec:
    component_a: str
    component_b: str
    fuzzer_name: str
    connection_count: int = 0
    ports: list[dict[str, str]] = field(default_factory=list)
    fuzzed_ports: list[dict[str, Any]] = field(default_factory=list)


class TopologyMutator:
    """Insert fuzzer components between communicating component pairs."""

    def __init__(self, base_seed: int = 0):
        self.base_seed = base_seed

    def mutate_file(self, seed_topology_path: str | Path) -> dict[str, Any]:
        path = Path(seed_topology_path)
        with path.open("r", encoding="utf-8") as f:
            topology = yaml.safe_load(f)

        if not isinstance(topology, dict):
            raise ValueError("Seed topology must be a YAML mapping")

        return self.mutate_topology(topology)

    def mutate_topology(self, topology: dict[str, Any]) -> dict[str, Any]:
        mutated: dict[str, Any] = dict(topology)

        components = list(mutated.get("components", []))
        wires = list(mutated.get("wires", []))

        component_port_types = self._build_port_type_index(components)
        pair_specs: dict[tuple[str, str], PairFuzzerSpec] = {}
        rewritten_wires: list[list[Endpoint]] = []

        for wire in wires:
            if not isinstance(wire, list):
                rewritten_wires.append(wire)
                continue

            edges = self._wire_to_connections(wire)
            if not edges:
                rewritten_wires.append(wire)
                continue

            for left, right in edges:
                if left.get("component") == right.get("component"):
                    # Keep self-loop wire unchanged.
                    rewritten_wires.append([left, right])
                    continue

                fuzzer_name, left_port_name, right_port_name = self._register_connection(
                    left,
                    right,
                    pair_specs,
                    component_port_types,
                )

                rewritten_wires.append([
                    dict(left),
                    {"component": fuzzer_name, "port": left_port_name},
                ])
                rewritten_wires.append([
                    {"component": fuzzer_name, "port": right_port_name},
                    dict(right),
                ])

        existing_names = {c.get("name") for c in components if isinstance(c, dict)}
        new_fuzzers: list[dict[str, Any]] = []
        for spec in pair_specs.values():
            if spec.fuzzer_name in existing_names:
                raise ValueError(
                    f"Cannot auto-generate fuzzer '{spec.fuzzer_name}': component already exists"
                )
            new_fuzzers.append(
                {
                    "name": spec.fuzzer_name,
                    "type": "fuzzer",
                    "config": {"fuzzed_ports": spec.fuzzed_ports},
                    "ports": {"system": spec.ports},
                }
            )

        mutated["components"] = components + new_fuzzers
        mutated["wires"] = rewritten_wires
        return mutated

    def dump_yaml(self, topology: dict[str, Any]) -> str:
        return yaml.safe_dump(topology, sort_keys=False)

    def save_topology(self, topology: dict[str, Any], output_path: str | Path) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            f.write(self.dump_yaml(topology))

    def _build_port_type_index(self, components: list[Any]) -> dict[tuple[str, str], str]:
        index: dict[tuple[str, str], str] = {}
        for comp in components:
            if not isinstance(comp, dict):
                continue
            name = comp.get("name")
            if not isinstance(name, str):
                continue

            ports = comp.get("ports", {})
            if not isinstance(ports, dict):
                continue

            for group in ("system", "environment"):
                entries = ports.get(group, [])
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    port_name = entry.get("name")
                    port_type = entry.get("type")
                    if isinstance(port_name, str) and isinstance(port_type, str):
                        index[(name, port_name)] = port_type
        return index

    def _wire_to_connections(self, wire: list[Any]) -> list[Connection]:
        endpoints = [self._normalize_endpoint(e) for e in wire]
        endpoints = [e for e in endpoints if e is not None]
        if len(endpoints) < 2:
            return []
        if len(endpoints) == 2:
            return [(endpoints[0], endpoints[1])]

        # For bus-like wires, connect each endpoint to the first endpoint.
        root = endpoints[0]
        return [(root, endpoint) for endpoint in endpoints[1:]]

    def _normalize_endpoint(self, endpoint: Any) -> Endpoint | None:
        if not isinstance(endpoint, dict):
            return None
        component = endpoint.get("component")
        port = endpoint.get("port")
        if not isinstance(component, str) or not isinstance(port, str):
            return None
        return {"component": component, "port": port}

    def _register_connection(
        self,
        left: Endpoint,
        right: Endpoint,
        pair_specs: dict[tuple[str, str], PairFuzzerSpec],
        component_port_types: dict[tuple[str, str], str],
    ) -> tuple[str, str, str]:
        left_component = left["component"]
        right_component = right["component"]

        pair = tuple(sorted((left_component, right_component)))
        comp_a, comp_b = pair
        fuzzer_name = f"Fuzzer_{comp_a}_{comp_b}"

        spec = pair_specs.get(pair)
        if spec is None:
            spec = PairFuzzerSpec(
                component_a=comp_a,
                component_b=comp_b,
                fuzzer_name=fuzzer_name,
            )
            pair_specs[pair] = spec

        spec.connection_count += 1
        idx = spec.connection_count

        left_is_a = left_component == comp_a
        endpoint_a = left if left_is_a else right
        endpoint_b = right if left_is_a else left

        port_type = self._infer_port_type(endpoint_a, endpoint_b, component_port_types)
        group_name = f"{port_type}_{idx}"
        port_a = f"{group_name}_a"
        port_b = f"{group_name}_b"

        spec.ports.append({"name": port_a, "type": port_type})
        spec.ports.append({"name": port_b, "type": port_type})
        spec.fuzzed_ports.append(
            {
                "name": group_name,
                "syst_side": port_a,
                "comp_side": port_b,
                "seed": self.base_seed + idx,
                "comp_to_syst": {
                    "enabled": False,
                    "strategies": [],
                },
                "syst_to_comp": {
                    "enabled": False,
                    "strategies": [],
                },
            }
        )

        if left_is_a:
            return fuzzer_name, port_a, port_b
        return fuzzer_name, port_b, port_a

    def _infer_port_type(
        self,
        endpoint_a: Endpoint,
        endpoint_b: Endpoint,
        component_port_types: dict[tuple[str, str], str],
    ) -> str:
        a_type = component_port_types.get((endpoint_a["component"], endpoint_a["port"]))
        b_type = component_port_types.get((endpoint_b["component"], endpoint_b["port"]))

        if a_type and b_type and a_type != b_type:
            raise ValueError(
                "Cannot insert fuzzer between mismatched port types: "
                f"{endpoint_a['component']}.{endpoint_a['port']} ({a_type}) vs "
                f"{endpoint_b['component']}.{endpoint_b['port']} ({b_type})"
            )

        return a_type or b_type or "bytes"
