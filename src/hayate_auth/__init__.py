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
from .oauth import OAuthProvider, github, google

__version__ = "0.3.0"

__all__ = [
    "Adapter",
    "Auth",
    "CryptoBackend",
    "OAuthProvider",
    "Pbkdf2Backend",
    "ScryptBackend",
    "UnsupportedHashError",
    "Where",
    "__version__",
    "default_backend",
    "github",
    "google",
]
