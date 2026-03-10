"""
sensors_fuzz.py
---------------
Fuzzing scenario for all OBCSensorsManager sensors with oracle validation.

Topology: sensors_fuzz.yaml
  - QEMU running CHESS_Pathfinder0FS
  - 10 per-sensor fuzzers (Fuzzer_Temp0..7, Fuzzer_IMU, Fuzzer_Mag)

For each sensor the test:
  1. Arms the fuzzer AND injects simulate_defect simultaneously
  2. Holds the fault for 20s (at 1Hz polling → at least 20 poll cycles,
     exceeding the 3-cycle failure threshold and 10-cycle backoff window)
  3. Clears the fault (sensor should auto-recover within 10 cycles)
  4. Waits a 20s recovery gap before the next sensor test

Oracle: reads the QEMU serial PTY (/tmp/qemu-serial-pty) and feeds lines into
FuzzOracle. Expected result per sensor: REJECTED (i.e. F' logs the failure).
"""

from nest_client import *
from nest_client.time import Time
from nest_client.fuzz_oracle import FuzzOracle, FuzzResult

import asyncio
import numpy as np

MAG_SENSITIVITY = 16384.0
MAG_OFFSET = 131072.0

import os as _os

# ---------------------------------------------------------------------------
# QUICK_TEST mode  —  set QUICK_TEST=1 to validate the oracle in ~40s
#   instead of the full 430s (10 sensors × 40s).
#   Fault window cut to the minimum viable (5s > 3 poll cycles @ 1Hz).
# ---------------------------------------------------------------------------
_QUICK = _os.environ.get("QUICK_TEST", "0") == "1"

ALL_SENSORS = [
    # (fuzzer_name,   sensor_peripheral, label_for_oracle)
    # Each sensor gets a unique label so each gets its own FuzzOracle instance.
    ("Fuzzer_IMU", "IIM-42652",  "IMU"),
] if _QUICK else [
    ("Fuzzer_Temp0", "PCT2075_0",  "Temperature_0"),
    ("Fuzzer_Temp1", "PCT2075_1",  "Temperature_1"),
    ("Fuzzer_Temp2", "PCT2075_2",  "Temperature_2"),
    ("Fuzzer_Temp3", "PCT2075_3",  "Temperature_3"),
    ("Fuzzer_Temp4", "PCT2075_4",  "Temperature_4"),
    ("Fuzzer_Temp5", "PCT2075_5",  "Temperature_5"),
    ("Fuzzer_Temp6", "PCT2075_6",  "Temperature_6"),
    ("Fuzzer_Temp7", "PCT2075_7",  "Temperature_7"),
    ("Fuzzer_IMU",   "IIM-42652",  "IMU"),
    ("Fuzzer_Mag",   "MMC5983MA",  "Magnetometer"),
]

# F' polls at 1 Hz, failure threshold = 3 consecutive failures.
# I2C timeouts take >1s each, so 3 failures take >5 seconds.
# FAULT_ACTIVE_S must be 15s to give a safe margin for 3 consecutive timeouts.
FAULT_ACTIVE_S = 15 if _QUICK else 20
RECOVERY_GAP_S = 5  if _QUICK else 20
TEST_STEP_S    = FAULT_ACTIVE_S + RECOVERY_GAP_S
BOOT_MARGIN_S  = 30   # seconds to allow QEMU + F' binary to boot and reach NOMINAL


# ---------------------------------------------------------------------------
# Sequences
# ---------------------------------------------------------------------------

@sequence
def env_ramp():
    """Set nominal environment conditions from the start."""
    with timeline() as t:
        t[0 * s] = set_env("temp",    EnvVarType.FLOAT, 23.0)
        t[0 * s] = set_env("accel",   EnvVarType.VEC3, np.array([0.0, 0.0, 0.0]))
        t[0 * s] = set_env("omega",   EnvVarType.VEC3, np.array([0.0, 0.0, 0.0]))
        t[0 * s] = set_env("B_field", EnvVarType.VEC3, np.array([
            MAG_OFFSET, MAG_OFFSET, MAG_OFFSET
        ]))
        # Ramp to non-trivial values
        t[10 * s] = set_env("temp",    EnvVarType.FLOAT, 35.0, lerp_over=60*s)
        t[10 * s] = set_env("accel",   EnvVarType.VEC3, np.array([0.5, 0.5, 9.8]), lerp_over=60*s)
        t[10 * s] = set_env("omega",   EnvVarType.VEC3, np.array([0.1, 0.2, 0.3]), lerp_over=60*s)
        t[10 * s] = set_env("B_field", EnvVarType.VEC3, np.array([
            MAG_OFFSET + MAG_SENSITIVITY * 0.3,
            MAG_OFFSET + MAG_SENSITIVITY * 0.2,
            MAG_OFFSET + MAG_SENSITIVITY * 0.1,
        ]), lerp_over=60*s)


@sequence
def check_qemu_running():
    """Verify QEMU is booted and running."""
    with timeline() as t:
        t[0 * s] = command("QEMU", "qmp_command", {"execute": "query-status"})
        t[0 * s] = event("QEMU", "qmp_response") \
            .where(lambda data: data.get('running') is True and data.get('status') == 'running') \
            .expect(within=2 * s)


def fault_test(fuzzer_name: str, sensor_name: str):
    """
    Arm fuzzer + inject defect simultaneously, then clear after FAULT_ACTIVE_S seconds.
    The fuzzer's set_fuzzing_select drops I2C traffic at the NEST level.
    The sensor's simulate_defect makes the peripheral itself return I2C errors.
    Both mechanisms together ensure ≥3 consecutive read failures reach F'.
    """
    @sequence
    def _fault():
        with timeline() as t:
            # 1. Enable Fuzzer (drops I2C traffic between QEMU and sensor)
            #    AND inject defect on the sensor peripheral simultaneously.
            t[0 * s]              = command(fuzzer_name, "set_fuzzing_select", True)
            t[0 * s]              = command(sensor_name, "simulate_defect", True)

            # 2. Wait for the failure to be registered by F' (needs >3 consecutive failures)
            # This is implicitly handled by the duration of FAULT_ACTIVE_S

            # 3. Disable Fuzzer and clear defect (restore I2C traffic)
            t[FAULT_ACTIVE_S * s] = command(fuzzer_name, "set_fuzzing_select", False)
            t[FAULT_ACTIVE_S * s] = command(sensor_name, "simulate_defect", False)
    return _fault()


# ---------------------------------------------------------------------------
# Main scenario
# ---------------------------------------------------------------------------

@scenario(topology_file="./sensors_fuzz.yaml")
def sensors_fuzz():
    """
    Fault-inject every sensor in turn and validate the oracle after each test.
    Total runtime ≈ 30 + 10 × 40 = 430 seconds (~7.2 min).

    Note: check_qemu_running() removed — qmp_command/qmp_response are not exposed
    by NEST for this topology. Boot readiness is covered by BOOT_MARGIN_S (30s).
    """
    with timeline() as t:
        t[0 * s] = env_ramp()

        for idx, (fuzzer, sensor, _label) in enumerate(ALL_SENSORS):
            offset = BOOT_MARGIN_S + idx * TEST_STEP_S
            t[offset * s] = fault_test(fuzzer, sensor)


# ---------------------------------------------------------------------------
# Standalone oracle runner
# ---------------------------------------------------------------------------

async def run_oracle_standalone():
    """
    Run the scenario and simultaneously tail the QEMU PTY to feed the oracle.
    Prints a per-sensor oracle result table at the end.

    Usage: python -m scenarios.sensors_fuzz
    """
    from nest_client.client import AsyncNestClient

    PTY = "/tmp/qemu-serial-pty"
    client = AsyncNestClient()

    # Per-sensor oracle instances
    oracles = {label: FuzzOracle(timeout_secs=FAULT_ACTIVE_S + 5)
               for _, _, label in ALL_SENSORS}

    # Track which oracle is active based on simulation time
    active_index = [0]
    pty_lines: list[str] = []

    async def tail_pty():
        """Continuously tail the F' serial output and feed lines to the active oracle."""
        import os
        pty_log = os.environ.get("NEST_PTY_LOG")
        if pty_log:
            # When run via run_fuzz_test.sh: Step 4 monitor owns the PTY and
            # streams everything to this log file. Tail it so we don't conflict.
            cmd = ["tail", "-F", pty_log]
        else:
            # Direct invocation: read the PTY ourselves.
            cmd = ["cat", PTY]

        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            while True:
                if proc.stdout is None:
                    break
                line = await proc.stdout.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").strip()
                # Skip auto-login annotations injected by the shell monitor
                if decoded and not decoded.startswith("[auto-login]"):
                    pty_lines.append(decoded)
                    idx = active_index[0]
                    if idx < len(ALL_SENSORS):
                        _, _, label = ALL_SENSORS[idx]
                        oracles[label].feed_log_line(decoded)
        except asyncio.CancelledError:
            pass
        finally:
            if proc is not None:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
                await proc.wait()

    pty_task = asyncio.create_task(tail_pty())

    try:
        # Advance active_index on each sensor's fault window
        async def advance_sensor_index():
            await asyncio.sleep(BOOT_MARGIN_S)
            for i in range(len(ALL_SENSORS)):
                active_index[0] = i
                await asyncio.sleep(TEST_STEP_S)

        index_task = asyncio.create_task(advance_sensor_index())
        result_list = await sensors_fuzz.run_async(client)
        await index_task

    finally:
        pty_task.cancel()
        try:
            await pty_task
        except asyncio.CancelledError:
            pass

    # Print results — each sensor now has a unique label so no reset/collision needed
    print("\n" + "=" * 60)
    print(" FUZZING ORACLE RESULTS")
    print("=" * 60)
    for fuzzer, sensor, label in ALL_SENSORS:
        result = oracles[label].evaluate()
        status = "✅ EXPECTED" if result == FuzzResult.SUCCESS_HANDLED else f"⚠️  {result.value}"
        print(f"  {sensor:<15} [{label:<20}] → {status}")
    print("=" * 60)

    # Validation results from event() assertions
    print("\nNEST event assertions:")
    for vr in result_list:
        icon = "✅" if vr.success else "❌"
        print(f"  {icon} {vr.op}")


if __name__ == "__main__":
    asyncio.run(run_oracle_standalone())
