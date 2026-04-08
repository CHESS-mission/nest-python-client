"""
nest_client
===========

Python client for the NEST simulator.
Provides:
- Client APIs
- Scenario DSL
- CLI entrypoint
"""

# Client APIs
from .client import NestClient, AsyncNestClient
from .exceptions import NestError, NestTimeoutError

# DSL
from .scenario import scenario
from .sequence import sequence, timeline, command, event, set_env
from .types import EnvVarType
from .time import m, s, ms, us
from .topology_mutator import TopologyMutator

# Version
from .__version__ import __version__

__all__ = [
    # Clients
    "NestClient",
    "AsyncNestClient",
    "NestError",
    "NestTimeoutError",

    # DSL
    "scenario",
    "sequence",
    "timeline",
    "command",
    "event",
    "set_env",
    "EnvVarType",
    "m",
    "s",
    "ms",
    "us",
    "TopologyMutator",

    # Metadata
    "__version__",
]

