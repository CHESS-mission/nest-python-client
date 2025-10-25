import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from nest_client.client import NestClient

# client = NestClient("ws://localhost:8080/ws")
client = NestClient("ws://127.0.0.1:3000/ws") # we get the port address after doing cargo run on nest

client.connect()
print("Connected to NEST WebSocket")

# try starting/stopping a simulation (may log errors if topology not loaded)
client.start()
status = client.wait_for_status("running", timeout=5)
print("Status:", status)

client.stop()
status = client.wait_for_status("ready", timeout=5)
print("Status:", status)

client.disconnect()
print("Disconnected")
