"""
Basic simulation scenario using the NEST Python client.

Runs a scripted sequence:
1. Connect to the NEST simulator
2. Upload topology
3. Run several start/stop cycles
4. Print status and logs for each step
"""

import time
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from nest_client.client import NestClient
from nest_client.utils import pretty_json

def main():
    client = NestClient()
    client.connect()

    try:
        client.load_topology_from_file("examples/topology_example.yaml")
        print("✅ Topology uploaded.")
    except FileNotFoundError:
        print("⚠️ No topology file found — running with default simulator state.")

    cycles = 3
    for i in range(1, cycles + 1):
        print(f"\n=== Cycle {i}/{cycles} ===")
        client.start()
        status = client.wait_for_status("running", timeout=10)
        print("Running state:", pretty_json(status))

        time.sleep(1.5)

        client.stop()
        status = client.wait_for_status("ready", timeout=10)
        print("Ready state:", pretty_json(status))

    client.disconnect()
    print("\n✅ Scenario completed successfully.")

if __name__ == "__main__":
    main()
