# API Reference

## Class: `NestClient`

| Method | Description |
|---------|--------------|
| `connect()` | Connect to the NEST WebSocket server |
| `disconnect()` | Disconnect and close session |
| `start()` | Start a running simulation |
| `stop()` | Stop the current simulation |
| `upload_topology(yaml: str)` | Upload YAML topology to NEST |
| `load_topology_from_file(path: str)` | Upload topology directly from file |
| `wait_for_status(state)` | Block until simulator reaches given state |

## Class: `AsyncNestClient`

Same API as `NestClient`, but all methods are `async def` coroutines.
