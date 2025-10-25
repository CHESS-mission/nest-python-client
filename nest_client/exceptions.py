"""
Custom exception classes for the NEST Python client.
"""

class NestError(Exception):
    """Base exception for all client errors."""
    pass

class NestTimeoutError(NestError):
    """Raised when waiting for a message times out."""
    pass

class NestConnectionError(NestError):
    """Raised when a connection to the simulator fails."""
    pass

class NestProtocolError(NestError):
    """Raised when the simulator sends malformed or unexpected messages."""
    pass
