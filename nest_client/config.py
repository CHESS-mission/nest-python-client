"""
Default configuration values for the NEST Python client.
"""

# Default WebSocket endpoint for local NEST simulator
DEFAULT_URL = "ws://localhost:3000/ws"

# Default timeout (seconds) for awaiting messages/events/logs
DEFAULT_TIMEOUT = 10.0

# Default logging level
LOG_LEVEL = "INFO"

def get_default_config() -> dict:
    """Return the default configuration as a dictionary."""
    return {
        "url": DEFAULT_URL,
        "timeout": DEFAULT_TIMEOUT,
        "log_level": LOG_LEVEL,
    }
