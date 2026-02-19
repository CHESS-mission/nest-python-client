from __future__ import annotations
import asyncio
from dataclasses import dataclass
import json
import logging
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List

from nest_client.client import AsyncNestClient
from nest_client.sequence import Command, Event, Sequence, SequenceOp, SetEnv
from nest_client.time import Time, s


logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    op: SequenceOp
    success: bool
    raw_event: Dict | None


class Scenario:
    def __init__(
        self,
        name: str,
        topology_file: Path,
        sequence: Sequence,
    ):
        self.name = name
        self.topology_file = topology_file
        self.sequence = sequence

        self._events: List[dict] = []
        self._errors: List[dict] = []
        self._start_time: float | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    # Synchronous API
    def run(self, client: AsyncNestClient) -> List[ValidationResult]:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.run_async(client))
        else:
            raise RuntimeError(
                "Scenario.run() called from inside an event loop. "
                "Use 'await scenario.run_async()' instead."
            )

    async def run_async(self, client: AsyncNestClient) -> List[ValidationResult]:
        results = []

        try:
            await self._start_simulation(client)
            await self._execute_sequence(client)
            results = await self._validate_events()
        finally:
            await self._end_simulation(client)

        return results

    # ------------------------------------------------------------------
    # Setup / Teardown
    # ------------------------------------------------------------------

    async def _start_simulation(self, client: AsyncNestClient):
        await client.connect()

        # Register listeners
        await client.add_listener(self._on_message)

        # Upload topology
        with open(self.topology_file, "r", encoding="utf-8") as f:
            topology = f.read()

        await client.upload_topology(topology)
        await client.start()

        # Wait until running
        await client.wait_for_status("running")

        self._start_time = time.monotonic()

    async def _end_simulation(self, client: AsyncNestClient):
        await client.stop()
        await client.disconnect()

    # ------------------------------------------------------------------
    # Message Handling
    # ------------------------------------------------------------------

    async def _on_message(self, msg: dict):
        msg_type = msg.get("type")

        if msg_type == "event":
            self._events.append(msg)
            logger.info(f"Received event: {msg}")

        elif msg_type == "error":
            self._errors.append(msg)
            raise RuntimeError(f"Simulation error: {msg}")

    # ------------------------------------------------------------------
    # Sequence Execution
    # ------------------------------------------------------------------

    async def _execute_sequence(self, client: AsyncNestClient):
        assert self._start_time is not None

        tasks = []

        ops = self.sequence.flatten()
        for op in ops:
            if isinstance(op.item, Command) or isinstance(op.item, SetEnv):
                delay = op.offset.as_unit(s)
                tasks.append(asyncio.create_task(self._schedule_op(op, delay, client)))

        # Determine total scenario duration
        total_duration = self.sequence.duration().as_unit(s)

        # Wait for all scheduled operations
        await asyncio.gather(*tasks)

        # Wait for remainder of duration
        elapsed = time.monotonic() - self._start_time
        remaining = total_duration - elapsed
        if remaining > 0:
            await asyncio.sleep(remaining)

    async def _schedule_op(self, op: SequenceOp, delay_s: float, client: AsyncNestClient):
        await asyncio.sleep(delay_s)
        await self._execute_op(op, client)

    async def _execute_op(self, op: SequenceOp, client: AsyncNestClient):
        logger.info(op)
        item = op.item

        if isinstance(item, Command):
            await client.send_command(
                item.component,
                item.name,
                json.loads(item.args_json) if item.args_json else {},
            )

        elif isinstance(item, SetEnv):
            await client.set_env(
                item.var,
                item.type,
                item.value,
                item.lerp_over,
            )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    async def _validate_events(self) -> List[ValidationResult]:
        results = []

        ops = self.sequence.flatten()
        for op in ops:
            if not isinstance(op.item, Event):
                continue

            event = op.item
            window_start = op.offset.as_unit(s)
            window_end = window_start + (
                event.within if event.within else op.scope_stack[-1].end # Parent scope
            ).as_unit(s)

            matched = False
            raw_event = None

            for e in self._events:
                if (
                    e.get("component") == event.component
                    and e.get("event") == event.name
                ):
                    if event.predicate and not event.predicate(e.get("data")):
                        continue

                    ts = e.get("timestamp", 0)
                    if window_start <= ts <= window_end:
                        matched = True
                        raw_event = e
                        break

            results += [ValidationResult(
                op,
                not (event.expect ^ matched),
                raw_event
            )]

        return results


# ------------------------------------------------------------------
# Scenario decorator
# ------------------------------------------------------------------

def scenario(topology_file: str):
    def decorator(fn: Callable[[], None]) -> Scenario:
        # Resolve module file path
        module = sys.modules[fn.__module__]
        assert module.__file__ is not None
        module_file = Path(module.__file__).resolve()
        module_dir = module_file.parent

        # Resolve topology relative to module
        resolved_topology = (module_dir / topology_file).resolve()

        if not resolved_topology.exists():
            raise FileNotFoundError(
                f"Topology file not found: {resolved_topology}"
            )

        def build_sequence() -> Sequence:
            from nest_client.sequence import Sequence, _timeline_stack

            if _timeline_stack:
                raise RuntimeError("@scenario cannot be used inside a sequence")

            seq = Sequence(label=fn.__name__)
            _timeline_stack.append(seq)
            try:
                fn()
            finally:
                _timeline_stack.pop()
            return seq

        scen = Scenario(
            name=fn.__name__,
            topology_file=resolved_topology,
            sequence=build_sequence(),
        )

        return scen

    return decorator
