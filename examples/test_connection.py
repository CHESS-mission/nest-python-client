from nest_client.client import NestClient

client = NestClient("ws://localhost:8080/ws")
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
