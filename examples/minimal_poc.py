"""
Minimal proof-of-concept script for the NEST Python Client.

Demonstrates:
- connecting to the NEST WebSocket
- uploading a topology YAML
- starting and stopping a simulation
- printing logs (real-time status updates) received from the simulator
"""

import time
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from nest_client.client import NestClient

def main():
    client = NestClient()

    print("Connecting to NEST simulator...")
    client.connect()

    # Upload a simple topology (if available)
    try:
        client.load_topology_from_file("examples/topology_example.yaml")
        print("Uploaded topology successfully.")
    except FileNotFoundError:
        print("No topology file found. Continuing without upload...")

    print("Starting simulation...")
    client.start()
    try:
        status = client.wait_for_status("running", timeout=10)
        print("Simulation started:", status)
    except Exception as e:
        print("⚠️ Warning:", e)
        print("Fetching current status manually...")
        print(client.wait_for_status("ready", timeout=5))

    # Wait until simulator reports 'running' status
    status = client.wait_for_status("running", timeout=5)
    print("Status:", status)

    # Wait a bit, then stop
    time.sleep(2)
    print("Stopping simulation...")
    client.stop()

    # Wait until simulator goes back to 'ready' state
    status = client.wait_for_status("ready", timeout=5)
    print("Status:", status)

    print("Disconnecting...")
    client.disconnect()
    print("✅ Done.")

if __name__ == "__main__":
    main()

