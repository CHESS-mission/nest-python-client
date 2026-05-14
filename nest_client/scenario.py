from __future__ import annotations
import asyncio
from dataclasses import dataclass
import json
import logging
import inspect
import time
import websockets
from pathlib import Path
from typing import Any, Callable, Dict, List

from nest_client.client import AsyncNestClient
from nest_client.mutators.topology_mutator import TopologyMutator
from nest_client.sequence import Command, Event, Sequence, SequenceOp, SetEnv
from nest_client.time import Time, s
#from nest_client.fuzz_oracle import FuzzOracle, FuzzResult


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
        mutate_topology: bool = False,
        persist_mutated_topology: bool = False,
        mutation_seed: int = 0,
        mutation_output_dir: Path | None = None,
        topology_mutation_transform: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        on_server_message: Callable[[dict], None] | None = None,
    ):
        self.name = name
        self.topology_file = topology_file
        self.sequence = sequence
        self.mutate_topology = mutate_topology
        self.persist_mutated_topology = persist_mutated_topology
        self.mutation_seed = mutation_seed
        self.mutation_output_dir = mutation_output_dir
        self.topology_mutation_transform = topology_mutation_transform
        self.on_server_message = on_server_message

        self._events: List[dict] = []
        self._errors: List[dict] = []
        self._start_time: float | None = None
        self.on_simulation_started: Callable | None = None

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
            if self.on_simulation_started is not None:
                self.on_simulation_started()
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

        topology = self._build_topology_yaml()

        await client.upload_topology(topology)
        await client.start()

        # Wait until running
        await client.wait_for_status("running")

        self._start_time = time.monotonic()

    def _build_topology_yaml(self) -> str:
        with open(self.topology_file, "r", encoding="utf-8") as f:
            seed_yaml = f.read()

        if not self.mutate_topology:
            return seed_yaml

        mutator = TopologyMutator(base_seed=self.mutation_seed)
        mutated = mutator.mutate_file(self.topology_file)
        if self.topology_mutation_transform is not None:
            mutated = self.topology_mutation_transform(mutated)

        if self.persist_mutated_topology:
            output_dir = self.mutation_output_dir or self.topology_file.parent / "mutations"
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / f"{self.topology_file.stem}.mutated.yaml"
            mutator.save_topology(mutated, output_path)
            logger.info("Saved mutated topology to %s", output_path)

        return mutator.dump_yaml(mutated)

    async def _end_simulation(self, client: AsyncNestClient):
        # stop() is best-effort: the server may have already closed the connection
        # (e.g. if QEMU crashed). Log the error but don't re-raise.
        try:
            await client.stop()
        except websockets.exceptions.ConnectionClosedError as e:
            pass  # Expected if QEMU or NEST closed first
        except Exception as e:
            logger.warning("stop() failed during teardown (ignored): %s", e)
        await client.disconnect()

    async def _monitor_oracle(self):
        """Runs in background: tails the QEMU PTY and feeds it to the FuzzOracle."""
        try:
            pty_path = "/tmp/qemu-serial-pty"
            process = await asyncio.create_subprocess_exec(
                "cat", pty_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            while True:
                if process.stdout is None:
                    break
                line_bytes = await process.stdout.readline()
                if not line_bytes:
                    break
                
                line = line_bytes.decode('utf-8', errors='replace').strip()
                if line:
                    self.oracle.feed_log_line(line)
        except asyncio.CancelledError:
            if process:
                process.kill()
        except Exception as e:
            logger.error(f"Oracle monitor error: {e}")

    # ------------------------------------------------------------------
    # Message Handling
    # ------------------------------------------------------------------

    async def _on_message(self, msg: dict):
        if self.on_server_message is not None:
            self.on_server_message(msg)

        msg_type = msg.get("type")

        if msg_type == "event":
            self._events.append(msg)
            logger.debug("Received event: %s", msg)

        elif msg_type == "error":
            self._errors.append(msg)
            # Don't raise: called as a fire-and-forget task; error is already
            # captured in _errors and forwarded via on_server_message callback.

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
        logger.debug("%s", op)
        item = op.item

        try:
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
        except Exception as e:
            # Swallow WS-drop errors mid-scenario so remaining timeline ops
            # still execute (or are at least attempted). The oracle evaluates
            # on whatever logs arrived before the connection dropped.
            logger.warning("Op failed (connection lost?): %s — %s", op, e)

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
            window_end = (
                op.offset + event.within if event.within else op.scope_stack[-1].end # Parent scope
            ).as_unit(s)

            matched = False
            raw_event = None

            for e in self._events:
                if (
                    e.get("component") == event.component
                    and e.get("event") == event.name
                ):
                    if event.predicate:
                        try:
                            data = e.get("data")
                            if data is None or not event.predicate(data):
                                continue
                        # Be permissive about KeyError to make predicates more ergonomic
                        # (i.e. predicate fails if key does not exist)
                        except KeyError:
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

def scenario(
    topology_file: str,
    *,
    mutate_topology: bool = False,
    persist_mutated_topology: bool = False,
    mutation_seed: int = 0,
    mutation_output_dir: str | None = None,
):
    def decorator(fn: Callable[[], None]) -> Scenario:
        # Resolve scenario file path
        module_file = inspect.getsourcefile(fn)
        if module_file is None:
            raise RuntimeError(f"Cannot determine source file for {fn}")

        module_file = Path(module_file).resolve()
        module_dir = module_file.parent
        module_dir = module_file.parent

        # Resolve topology relative to module
        resolved_topology = (module_dir / topology_file).resolve()

        if not resolved_topology.exists():
            raise FileNotFoundError(
                f"Topology file not found: {resolved_topology}"
            )

        resolved_output_dir = None
        if mutation_output_dir is not None:
            resolved_output_dir = (module_dir / mutation_output_dir).resolve()

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
            mutate_topology=mutate_topology,
            persist_mutated_topology=persist_mutated_topology,
            mutation_seed=mutation_seed,
            mutation_output_dir=resolved_output_dir,
        )

        return scen

    return decorator
