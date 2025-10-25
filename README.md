# 🛰️ NEST Python Client

A Python interface for the **CHESS NEST simulator**, allowing users to interact with the simulator through WebSocket instead of Rust or the web frontend.

This client can:
- Connect to the running NEST simulator
- Upload topologies (YAML files)
- Start and stop simulations
- Receive real-time logs, status updates, and events

---

## 🚀 Installation

1. Clone the repository:
```
git clone https://github.com/CHESS-mission/nest-python-client.git
cd nest-python-client
```

2. (Recommended) Create and activate a virtual environment:
```
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```
pip install -r requirements.txt
```

---

## ⚙️ Running the NEST simulator

Before running the Python client, start the simulator from the main NEST repository:

```
cd ../nest
cargo run
```

You should see:
```
listening on http://127.0.0.1:3000
```

---

## 🧠 Basic usage

```
from nest_client import NestClient

client = NestClient()  # Defaults to ws://localhost:3000/ws

client.connect()
client.load_topology_from_file("examples/topology_example.yaml")
client.start()

status = client.wait_for_status("running", timeout=10)
print(status)

client.stop()
client.disconnect()
```
---

## 🧩 Example scripts

You can run included examples directly:
```
python examples/minimal_poc.py
```

Or use the helper script:
```
bash scripts/run_poc.sh
```

---

## ⚠️ Requirements

- Python 3.10+
- Websockets 12+
- A running instance of the NEST simulator (`cargo run` from the main repo)

---

## 📄 License

MIT License © 2025 CHESS Mission
