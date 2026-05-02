from typing import Dict
from nest_client import *
from nest_client.time import Time


@sequence
def check_qemu(component_name: str):
    with timeline() as t:
        t[0 * s] = command(component_name, "qmp_command", { "execute": "query-status" })
        t[0 * s] = event(component_name, "qmp_response") \
            .where(lambda data: data['running'] == True and data['status'] == 'running') \
            .expect(within=500 * ms)


@sequence
def check_packet(cpu_id: int, temp_from: float, temp_to: float, within: Time):
    def check_data(data: Dict) -> bool:
        return data['start_word'].lower() == '0xdeadbeef' and \
               data['cpu_id'] == cpu_id and \
               temp_from <= data['temperature'] <= temp_to

    with timeline() as t:
        t[0 * s] = event("Transceiver", "packet_received") \
            .where(check_data) \
            .expect(within=within)


@sequence
def temperature_ramp(from_: float, to: float, over: Time):
    with timeline() as t:
        t[0 * s] = set_env("temp", EnvVarType.FLOAT, from_)
        t[0 * s] = set_env("temp", EnvVarType.FLOAT, to, lerp_over=over)


@sequence
def init():
    with timeline() as t:
        # Let VMs boot
        t[25 * s] = check_qemu("CPU_A")
        t[25 * s] = check_qemu("CPU_B")


@sequence
def test_CPU_temp_static(cpu_id: int):
    with timeline() as t:
        t[0 * s] = set_env("temp", EnvVarType.FLOAT, 23.0)
        t[0 * s] = check_packet(cpu_id, 22.9, 23.1, 3*s)


@sequence
def test_CPU_temp_ramp(cpu_id: int):
    with timeline() as t:
        t[0 * s] = temperature_ramp(23.0, 42.0, 10*s) >> check_packet(cpu_id, 41.9, 42.1, 3*s)
        t[5 * s] = check_packet(cpu_id, 30.0, 35.0, 2*s)


@sequence
def test_CPU(cpu_id: int, delay: Time=0*s):
    with timeline() as t:
        t[delay] = event("Transceiver", "packet_received") \
            .where(lambda data: data['cpu_id'] != cpu_id) \
            .forbid()
        t[delay] = test_CPU_temp_static(cpu_id) >> test_CPU_temp_ramp(cpu_id)


@sequence
def stop_CPU(component_name: str):
    with timeline() as t:
        t[0 * s] = command(component_name, "qmp_command", { "execute": "stop" })


@sequence
def resume_CPU(component_name: str):
    with timeline() as t:
        t[0 * s] = command(component_name, "qmp_command", { "execute": "cont" })


@scenario(topology_file="./demo.yaml")
def demo():
    with timeline() as t:
        t[0 * s] = init() >> \
                   test_CPU(0) >> \
                   stop_CPU("CPU_A") >> \
                   test_CPU(1, 25*s) >> \
                   resume_CPU("CPU_A") >> \
                   test_CPU(0, 2*s)

