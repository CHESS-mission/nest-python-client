from nest_client import *
from nest_client.time import Time

TEMP_VALID_MIN = -40.0
TEMP_VALID_MAX = 85.0


@sequence
def check_qemu(component_name: str):
    with timeline() as t:
        t[0 * s] = command(component_name, "qmp_command", {"execute": "query-status"})
        t[0 * s] = event(component_name, "qmp_response") \
            .where(lambda data: data['running'] == True and data['status'] == 'running') \
            .expect(within=500 * ms)


@sequence
def init():
    with timeline() as t:
        t[30 * s] = check_qemu("CPU_A")
        t[30 * s] = check_qemu("CPU_B")


@sequence
def check_temperature_sanity(cpu_id: int, duration: Time):
    """Forbid any Transceiver packet carrying a temperature outside the valid range.

    Good FS (with sanity check): fuzzer noise filtered before reaching Transceiver -> passes.
    Buggy FS (no sanity check): garbage temperatures forwarded to Transceiver -> FORBID fires.
    """
    with timeline() as t:
        t[0 * s] = event("Transceiver", "packet_received") \
            .where(lambda data: (
                data['cpu_id'] == cpu_id and (
                    data['temperature'] < TEMP_VALID_MIN or
                    data['temperature'] > TEMP_VALID_MAX
                )
            )) \
            .forbid()
        t[0 * s] = event("Transceiver", "packet_received") \
            .where(lambda data: (
                data['cpu_id'] == cpu_id and
                TEMP_VALID_MIN <= data['temperature'] <= TEMP_VALID_MAX
            )) \
            .expect(within=10 * s)


@scenario(topology_file="./demo.yaml")
def fuzzing_regression():
    with timeline() as t:
        t[0 * s] = init() >> check_temperature_sanity(0, 30 * s)
