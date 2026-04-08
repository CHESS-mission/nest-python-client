from nest_client import *

import numpy as np

# This is likely that the scaling issue is a WASM implementation issue
MAG_SENSITIVITY = 16384.0
MAG_OFFSET = 131072.0

def gauss_to_raw(gauss):
    return MAG_OFFSET + gauss * MAG_SENSITIVITY

@sequence
def env_ramp():
    with timeline() as t:
        t[0 * s] = set_env("temp", EnvVarType.FLOAT, 23.0)
        t[0 * s] = set_env("accel", EnvVarType.VEC3, np.array([0, 0, 0]))
        t[0 * s] = set_env("omega", EnvVarType.VEC3, np.array([0, 0, 0]))
        t[0 * s] = set_env("B_field", EnvVarType.VEC3, np.array([gauss_to_raw(0.0), gauss_to_raw(0.0), gauss_to_raw(0.0)]))

        t[10 * s] = set_env("temp", EnvVarType.FLOAT, 42.0, lerp_over=300*s)
        t[10 * s] = set_env("accel", EnvVarType.VEC3, np.array([1.0, 2.0, 3.0]), lerp_over=300*s)
        t[10 * s] = set_env("omega", EnvVarType.VEC3, np.array([2.0, 4.0, 6.0]), lerp_over=300*s)
        t[10 * s] = set_env("B_field", EnvVarType.VEC3, np.array([gauss_to_raw(3.0), gauss_to_raw(3.0), gauss_to_raw(3.0)]), lerp_over=300*s)


@scenario(topology_file="./sensors.yaml")
def sensors():
    with timeline() as t:
        t[0 * s] = env_ramp()

        t[3 * s] = command("QEMU", "qmp_command", { "execute": "query-status" })
        t[3 * s] = event("QEMU", "qmp_response") \
            .where(lambda data: data['running'] == True and data['status'] == 'running') \
            .expect(within=500 * ms)

        with t.offset(30*s, "defect_loop"):
            for i in range(10):
                t[60 * i * s] = command("MMC5983MA", "simulate_defect", True)
                t[(30 + 60 * i) * s] = command("MMC5983MA", "simulate_defect", False)

