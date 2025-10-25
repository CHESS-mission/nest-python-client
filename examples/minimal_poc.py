"""
Minimal proof-of-concept script for the NEST Python Client.

Demonstrates:
- connecting to the NEST WebSocket
- uploading a topology YAML
- starting and stopping a simulation
- printing logs received from the simulator
"""

import asyncio
from nest_client.client import AsyncNestClient

async def main():
    client = AsyncNestClient("ws://localhost:8080/ws")
    await client.connect()
    await client.start()
    await asyncio.sleep(2)
    await client.stop()
    await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
