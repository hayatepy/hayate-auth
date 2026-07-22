"""hayate-auth: authentication for hayate as a pure fetch handler."""

from .adapter import Adapter, Where
from .auth import Auth
from .crypto import (
    CryptoBackend,
    Pbkdf2Backend,
    ScryptBackend,
    UnsupportedHashError,
    default_backend,
)

__version__ = "0.1.0"

__all__ = [
    "Adapter",
    "Auth",
    "CryptoBackend",
    "Pbkdf2Backend",
    "ScryptBackend",
    "UnsupportedHashError",
    "Where",
    "__version__",
    "default_backend",
]
