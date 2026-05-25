"""SEU Workload Generator
This will be a more interesting workload as soon as we add more subsystems

What this script drives:
    obcSensorsManager  — by varying temp / accel / omega / B_field at 1-2 Hz
                          across nominal, threshold and out-of-range values.
                          Exercises sensor processing, range-check FATAL
                          paths, and the telemetry update path on every cycle.
    eventAction (EA)   — sensor patterns near safety thresholds drive the
                          NOMINAL ↔ SAFE state machine transitions, which
                          also feeds the PAIRWISE invariant check.
    Health::Run        — indirectly, by keeping component queues busy so a
                          missed ping (from corruption) actually trips
                          warnCycles within the observation window.
    M4B switching      — periodic CPU mux toggles exercise the failover code
                          path.

"""
from __future__ import annotations

import logging
import os
import random
import signal
import sys
import time

import numpy as np
from nest_client.client import NestClient
from nest_client.types import EnvVarType


# configuration via env vars so docker-compose can tune without code edits ──
NEST_URL       = os.environ.get("NEST_URL", "ws://nest-server-seu:3000/ws")
CYCLE_DELAY_S  = float(os.environ.get("WORKLOAD_CYCLE_S", 3.0))   # gap between stimuli
JITTER_S       = float(os.environ.get("WORKLOAD_JITTER_S", 1.5))  # random ± delay
LOG_LEVEL      = os.environ.get("WORKLOAD_LOG", "INFO")
RANDOM_SEED    = int(os.environ.get("WORKLOAD_SEED", "1234"))

logging.basicConfig(level=LOG_LEVEL,
                    format="%(asctime)s workload  %(levelname)s  %(message)s")
log = logging.getLogger("seu_workload")

# sensor stimulus tables 
# Each list is a sequence of values to push at 0.5s spacing during the stimulus.
# Mix of nominal, near-threshold and clearly out-of-range to drive both the
# common path AND the range-check FATAL paths in obcSensorsManager.

NOMINAL_TEMP_C   = 35.0
TEMP_PROFILES = [
    [25.0, 30.0, 35.0, 40.0, 35.0],               # nominal sweep
    [35.0, 55.0, 75.0, 85.0, 65.0, 35.0],         # ramp toward upper warn
    [35.0, 15.0,  5.0, -5.0, 25.0, 35.0],         # ramp toward lower warn
    [35.0, 95.0, 35.0],                            # impulse to extreme
]

ACCEL_PROFILES = [
    [(0.5, 0.5, 9.8), (0.5, 0.5, 9.8)],                                   # nominal
    [(0.5, 0.5, 9.8), (1.5, 0.5, 9.8), (0.5, 1.5, 9.8), (0.5, 0.5, 9.8)], # small jitter
    [(0.5, 0.5, 9.8), (5.0, 5.0, 9.8), (0.5, 0.5, 9.8)],                  # impulse
    [(0.5, 0.5, 9.8), (0.0, 0.0, 0.0), (0.5, 0.5, 9.8)],                  # freefall hint
]

OMEGA_PROFILES = [
    [(0.1, 0.2, 0.3), (0.1, 0.2, 0.3)],
    [(0.1, 0.2, 0.3), (0.5, 0.2, 0.3), (0.1, 0.5, 0.3), (0.1, 0.2, 0.5)],
    [(0.1, 0.2, 0.3), (2.0, 2.0, 2.0), (0.1, 0.2, 0.3)],                  # high tumble
]


def _bfield(scale: float = 1.0):
    """Build a B_field vec3 — values match the magnetometer raw-counts model."""
    OFF, SENS = 131072.0, 16384.0
    return np.array([OFF + SENS * 0.3 * scale,
                     OFF + SENS * 0.2 * scale,
                     OFF + SENS * 0.1 * scale])


BFIELD_PROFILES = [
    [_bfield(1.0)],                                                       # nominal
    [_bfield(0.5), _bfield(1.0), _bfield(1.5)],                          # small tilt
    [_bfield(0.0), _bfield(2.0), _bfield(1.0)],                          # impulse
]


# stimulus functions 

def stress_temperature(rng: random.Random, nc: NestClient) -> str:
    profile = rng.choice(TEMP_PROFILES)
    for t in profile:
        nc.set_env("temp", EnvVarType.FLOAT, t)
        time.sleep(0.5)
    return f"temp profile len={len(profile)} max={max(profile):.1f}°C"


def stress_accel(rng: random.Random, nc: NestClient) -> str:
    profile = rng.choice(ACCEL_PROFILES)
    for ax, ay, az in profile:
        nc.set_env("accel", EnvVarType.VEC3, np.array([ax, ay, az]))
        time.sleep(0.5)
    return f"accel profile len={len(profile)}"


def stress_omega(rng: random.Random, nc: NestClient) -> str:
    profile = rng.choice(OMEGA_PROFILES)
    for ox, oy, oz in profile:
        nc.set_env("omega", EnvVarType.VEC3, np.array([ox, oy, oz]))
        time.sleep(0.5)
    return f"omega profile len={len(profile)}"


def stress_bfield(rng: random.Random, nc: NestClient) -> str:
    profile = rng.choice(BFIELD_PROFILES)
    for v in profile:
        nc.set_env("B_field", EnvVarType.VEC3, v)
        time.sleep(0.5)
    return f"B_field profile len={len(profile)}"


def stress_mux_toggle(rng: random.Random, nc: NestClient) -> str:
    # M4B mux: switch the OBC perspective between CPU_A and CPU_B.
    # Exercises the switching code path on every toggle.
    nc.send_command("M4B", "switch_back_to_a7a", "{}")
    return "M4B → A7A switch"


STIMULI = [
    stress_temperature,
    stress_accel,
    stress_omega,
    stress_bfield,
    stress_mux_toggle,
]


# main loop

_running = True


def _shutdown(signum, _frame):
    global _running
    log.info(f"signal {signum} received — finishing current stimulus then exiting")
    _running = False


def main() -> int:
    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    log.info(f"connecting NEST_URL={NEST_URL}  cycle={CYCLE_DELAY_S}s ±{JITTER_S}s  seed={RANDOM_SEED}")
    rng = random.Random(RANDOM_SEED)

    # Retry connection — nest-server may take a few seconds after compose start.
    nc = None
    for attempt in range(30):
        try:
            nc = NestClient(url=NEST_URL).__enter__()
            log.info(f"connected to NEST on attempt {attempt + 1}")
            break
        except Exception as e:
            log.info(f"NEST connect attempt {attempt + 1} failed ({e}); retrying in 2s")
            time.sleep(2.0)
    if nc is None:
        log.error("could not reach NEST; exiting")
        return 1

    cycle = 0
    try:
        while _running:
            cycle += 1
            stim = rng.choice(STIMULI)
            try:
                summary = stim(rng, nc)
                log.info(f"cycle {cycle:4d}  {stim.__name__:<20}  {summary}")
            except Exception as e:
                log.warning(f"cycle {cycle:4d}  {stim.__name__:<20}  FAILED: {e}")
            # Random ± jitter so stimuli aren't phase-locked to SEU injection rate.
            delay = max(0.1, CYCLE_DELAY_S + rng.uniform(-JITTER_S, JITTER_S))
            time.sleep(delay)
    finally:
        try:
            nc.__exit__(None, None, None)
        except Exception:
            pass
        log.info(f"workload generator exiting after {cycle} cycles")

    return 0


if __name__ == "__main__":
    sys.exit(main())
