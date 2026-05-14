from __future__ import annotations

import concurrent.futures
import logging
import random
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from nest_client.client import AsyncNestClient
from nest_client.remote.config import BASE_PORT, RemoteConfig
from nest_client.remote.ssh_runner import (
    SSHTunnel,
    launch_server_instance,
    ssh_exec,
    stop_server_instance,
    wait_for_websocket,
)
from nest_client.scenario import Scenario, ValidationResult

logger = logging.getLogger(__name__)


@dataclass
class ParallelRunResult:
    instance_index: int
    port: int
    seed: int
    scenario: Scenario
    results: list[ValidationResult]
    run_dir: Path


def _run_one_instance(
    descriptor,
    descriptor_path: Path,
    instance_index: int,
    local_port: int,
    seed: int,
    run_dir: Path,
    remote_config: RemoteConfig,
    dashboard=None,
) -> ParallelRunResult:
    """
    Full lifecycle for one instance: launch container, tunnel, run scenario, teardown.
    Everything runs in this thread so all log messages land in run_dir/run.log.
    """
    import json as _json
    from nest_client.mutators.descriptor_runner import (
        _attach_run_log_handler,
        _build_scenario,
        _detach_run_log_handler,
        _write_run_artifacts,
        _write_validation_report,
    )
    from nest_client.remote.dashboard import Phase
    from nest_client.remote.ssh_runner import _container_name

    instance_descriptor = deepcopy(descriptor)
    instance_descriptor.run.seed = seed

    scenario, scenario_seed, selection_summary = _build_scenario(instance_descriptor)
    scenario.persist_mutated_topology = True
    scenario.mutation_output_dir = run_dir

    log_handler = _attach_run_log_handler(run_dir)
    server_log = open(run_dir / "server.log", "w", encoding="utf-8")
    tunnel: SSHTunnel | None = None
    results: list[ValidationResult] = []

    try:
        # --- Infrastructure setup ---
        if dashboard is not None:
            dashboard.update(instance_index, Phase.LAUNCHING)
        host_port = launch_server_instance(remote_config, instance_index)

        if dashboard is not None:
            dashboard.update(instance_index, Phase.CONNECTING)
        tunnel = SSHTunnel(
            remote_config,
            local_port=local_port,
            remote_host="localhost",
            remote_port=host_port,
        )
        tunnel.start()
        tunnel._check_alive()

        logger.info("Waiting for instance %d on port %d…", instance_index, local_port)
        if not wait_for_websocket("localhost", local_port, remote_config.server_ready_timeout):
            raise RuntimeError(
                f"Instance {instance_index} (local port {local_port}) did not become ready "
                f"within {remote_config.server_ready_timeout}s"
            )
        logger.info("Instance %d is ready.", instance_index)

        # --- Scenario ---
        def _on_server_msg(msg: dict) -> None:
            server_log.write(_json.dumps(msg) + "\n")
            server_log.flush()
            if dashboard is not None:
                dashboard.on_server_msg(instance_index, msg)

        scenario.on_server_message = _on_server_msg

        if dashboard is not None:
            def _on_started():
                dashboard.set_simulation_started(instance_index)
            scenario.on_simulation_started = _on_started

        _write_run_artifacts(
            run_dir,
            descriptor_path,
            instance_descriptor,
            scenario,
            scenario_seed,
            selection_summary,
        )

        url = f"ws://localhost:{local_port}/ws"
        logger.info("Instance %d: connecting to %s (seed=%d)", instance_index, url, seed)
        if dashboard is not None:
            dashboard.update(instance_index, Phase.RUNNING)

        client = AsyncNestClient(url)
        try:
            results = scenario.run(client)
        except Exception as exc:
            if dashboard is not None:
                dashboard.update(instance_index, Phase.FAILED, error_msg=str(exc))
            raise

        n_pass = sum(r.success for r in results)
        n_fail = len(results) - n_pass
        _write_validation_report(run_dir, scenario, results)
        if dashboard is not None:
            dashboard.update(instance_index, Phase.DONE, passed=n_pass, failed=n_fail)

    finally:
        # --- Teardown ---
        try:
            container_logs = ssh_exec(remote_config, f"docker logs {_container_name(instance_index)} 2>&1")
            (run_dir / "container.log").write_text(container_logs, encoding="utf-8")
        except Exception as exc:
            logger.warning("Could not fetch container logs for instance %d: %s", instance_index, exc)

        if tunnel is not None:
            tunnel.stop()
        stop_server_instance(remote_config, instance_index)

        _detach_run_log_handler(log_handler)
        server_log.close()

    return ParallelRunResult(
        instance_index=instance_index,
        port=local_port,
        seed=seed,
        scenario=scenario,
        results=results,
        run_dir=run_dir,
    )


def run_parallel_remote(
    descriptor,
    remote_config: RemoteConfig,
    descriptor_path: Path,
    dashboard=None,
) -> list[ParallelRunResult]:
    """
    Spawn n parallel workers, each owning the full lifecycle of one instance.
    """
    n = descriptor.run.n_instances
    local_ports = [BASE_PORT + i for i in range(n)]
    indices = list(range(n))

    base_seed = descriptor.run.seed
    if base_seed is None:
        base_seed = random.randint(0, 99999)
    seeds = [base_seed + i for i in range(n)]

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    parent_run_dir = descriptor.run.artifacts_dir / f"{stamp}-{descriptor.scenario.name}"
    parent_run_dir.mkdir(parents=True, exist_ok=True)

    instance_run_dirs = [parent_run_dir / f"instance-{i}" for i in indices]
    for d in instance_run_dirs:
        d.mkdir(parents=True, exist_ok=True)

    parallel_results: list[ParallelRunResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as executor:
        future_to_idx = {
            executor.submit(
                _run_one_instance,
                descriptor,
                descriptor_path,
                i,
                local_ports[i],
                seeds[i],
                instance_run_dirs[i],
                remote_config,
                dashboard,
            ): i
            for i in indices
        }
        for future in concurrent.futures.as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                parallel_results.append(future.result())
            except Exception as exc:
                logger.error("Instance %d failed: %s", idx, exc)
                raise

    parallel_results.sort(key=lambda r: r.instance_index)
    return parallel_results
