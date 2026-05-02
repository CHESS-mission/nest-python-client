# NEST Client

A Python client for [NEST](https://github.com/CHESS-mission/nest).

Features:

- Connect to the running NEST simulator
- Upload topologies (YAML files)
- Start and stop simulations
- Receive real-time logs, status updates, and events
- Execute test scenarios

## Installation

You can install the client locally with pip:

```bash
pip install -e .
```

## Usage

The client ships with an interactive shell that can be invoked using
`nest-client` with no positional aguments.

```bash
nest-client
```

To list available scenarios in a python module, use `list`.

```bash
nest-client list scenarios
```

To display the timeline of a specific scenario, use `show`.

```bash
nest-client show scenarios/sensors.py:sensors
```

Finally, use `run` to execute a scenario.

```bash
nest-client run scenarios/sensors.py:sensors
```

## Descriptor-Driven Mutation + Run

You can drive both scenario mutation and topology mutation from one descriptor file,
then run the resulting setup directly.

Example descriptor: [scenarios/demo_descriptor.yaml](scenarios/demo_descriptor.yaml)

CHIPS field-aware descriptor example:
[scenarios/demo_descriptor_chips.yaml](scenarios/demo_descriptor_chips.yaml)

```bash
nest-client run-mutator scenarios/demo_descriptor.yaml
```

Each descriptor run writes trace artifacts to `scenarios/mutations` by default,
including the mutated topology YAML and the mutated scenario sequence.

`run-mutator` always mutates both the scenario timeline and topology.
The descriptor no longer accepts `topology` blocks, `scenario.mutate`,
`topology.mutate`, or `scenario.seed`.

Use `run.seed` as a single shared seed for both scenario and topology mutation.
If omitted, a random seed is generated and recorded in run artifacts.

Scenario mutation now infers fuzzer command targets from topology mutation.
Instead of listing fuzzer IDs explicitly, set `scenario.region` in the descriptor:

- `system`: use all discovered fuzzers in the mutated topology
- `ComponentName`: use fuzzers connected to one component
- `[ComponentA, ComponentB]`: union of fuzzers touching any listed component

Start/stop command injection is probability-driven and immediate at timeline
insertion points; delay settings are no longer used.

If the selected region resolves to no fuzzers, `run-mutator` fails fast with a
clear error before starting the simulation.

### CHIPS Protocol-Aware Fuzzing

You can attach a CHIPS protocol model and field-aware strategy selection in the
descriptor. This lets the fuzzer mutate decoded CHIPS frames (`seq`, `command`,
`payload`, `is_response`) and re-encode valid packets with recomputed CRC.

```yaml
protocol:
	kind: chips
	spec: protocols/chips.yaml

fuzz:
	chips:
		mode: typed        # random | typed
		fields: [seq, command, payload]
		payload_mode: bitflip   # bitflip | random | boundary | truncate | extend
```

When this block is present, `run-mutator` injects a `chips_frame` strategy into
the selected fuzzer groups for both directions.

#### `mode`

- `random`: payload mutation uses `payload_mode` directly (bit flips, random fill, boundary fill, truncate, or extend).
- `typed`: payload mutation first tries command-aware typing from `protocol.spec` (per-component command map), then falls back to random payload mutation if no command type matches.

Important behavior for `typed`:

- Component payload schemas are resolved per fuzzer from connected component names (and `Fuzzer_A_B` naming tokens).
- If no component schema matches a target fuzzer/group, a warning is logged and payload mutation falls back to random techniques.

#### `fields`

`fields` selects which CHIPS frame fields can be mutated.

- `seq`: mutate sequence byte.
- `command`: mutate 7-bit command ID.
- `payload`: mutate payload bytes using `payload_mode` (or typed rules when `mode: typed`).
- `is_response`: optionally toggle request/response flag bit.

You can combine fields, for example:

- `[seq, command, payload]`: mutate header + payload.
- `[payload]`: mutate payload only.

#### `payload_mode`

`payload_mode` defines how payload bytes are changed:

- `bitflip`: probabilistic bit flips, controlled by `payload_flip_prob` and `max_payload_flips`.
- `random`: replace all payload bytes with random values.
- `boundary`: fill payload with `0x00` or `0xFF`.
- `truncate`: shorten payload to a smaller random length.
- `extend`: append random bytes, up to `max_payload_extend`.

Notes:

- `payload_mode` is used directly in `mode: random`.
- In `mode: typed`, `payload_mode` is still used as fallback behavior when typed mutation does not apply.

#### Typed Protocol Spec Shape

For typed mutation, define payload typing per component in the protocol file:

```yaml
name: chips
components:
  Transceiver:
    payload_types:
      "0x10": ascii
      "0x20": u16_le
      "0x21": u32_le
  Mux:
    payload_types:
      "0x30": bytes
```

Allowed payload type values are:

- `ascii`
- `u16_le`
- `u32_le`
- `bytes`
