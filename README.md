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

```bash
nest-client run-mutator scenarios/demo_descriptor.yaml
```

Each descriptor run writes trace artifacts to `scenarios/mutations` by default,
including the mutated topology YAML and the mutated scenario sequence.
