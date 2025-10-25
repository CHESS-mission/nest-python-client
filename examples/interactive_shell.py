"""
Interactive command-line shell for the NEST Python client.

Lets you manually:
- connect / disconnect
- start / stop simulations
- upload topology
- view logs and statuses

Usage:
    python examples/interactive_shell.py
"""

import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from nest_client.client import NestClient

def print_help():
    print("""
Available commands:
  connect                 Connect to the NEST simulator
  disconnect              Disconnect the client
  upload <file>           Upload a topology YAML file
  start                   Start simulation
  stop                    Stop simulation
  status <state>          Wait for given status (idle, ready, running)
  quit / exit             Close client and exit
  help                    Show this help message
""")

def main():
    client = NestClient()
    connected = False

    print("NEST Interactive Shell — type 'help' for options.\n")

    while True:
        try:
            cmd = input("> ").strip().split()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting shell...")
            break

        if not cmd:
            continue

        match cmd[0]:
            case "help":
                print_help()

            case "connect":
                if connected:
                    print("Already connected.")
                else:
                    client.connect()
                    connected = True
                    print("Connected to NEST.")

            case "disconnect":
                if connected:
                    client.disconnect()
                    connected = False
                    print("Disconnected.")
                else:
                    print("Not connected.")

            case "upload":
                if len(cmd) < 2:
                    print("Usage: upload <path_to_yaml>")
                    continue
                try:
                    client.load_topology_from_file(cmd[1])
                    print(f"Uploaded topology from {cmd[1]}")
                except Exception as e:
                    print(f"Error: {e}")

            case "start":
                client.start()
                print("Simulation started.")

            case "stop":
                client.stop()
                print("Simulation stopped.")

            case "status":
                if len(cmd) < 2:
                    print("Usage: status <idle|ready|running>")
                    continue
                try:
                    s = client.wait_for_status(cmd[1], timeout=10)
                    print("Status:", s)
                except Exception as e:
                    print(f"Error: {e}")

            case "quit" | "exit":
                if connected:
                    client.disconnect()
                print("Goodbye.")
                break

            case _:
                print(f"Unknown command: {cmd[0]} (type 'help' for options)")

    if connected:
        client.disconnect()

if __name__ == "__main__":
    main()
