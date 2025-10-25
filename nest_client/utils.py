"""
Utility functions for the NEST Python client.
"""

import json
# import yaml

def load_yaml(path: str) -> str:
    """Load a YAML file and return its contents as a UTF-8 string."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def pretty_json(obj: dict) -> str:
    """Return a nicely formatted JSON string for debug/logging."""
    return json.dumps(obj, indent=4, ensure_ascii=False)
