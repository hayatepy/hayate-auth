"""hayate-auth: authentication for hayate as a pure fetch handler."""

from . import totp
from .adapter import Adapter, Where
from .auth import Auth
from .authorization_server import AuthorizationServer
from .crypto import (
    CryptoBackend,
    Pbkdf2Backend,
    ScryptBackend,
    UnsupportedHashError,
    default_backend,
)
from .oauth import OAuthProvider, github, google
from .passkey import PasskeyConfig
from .plugin import AuthPlugin

__version__ = "0.7.0"

__all__ = [
    "Adapter",
    "Auth",
    "AuthPlugin",
    "AuthorizationServer",
    "CryptoBackend",
    "OAuthProvider",
    "PasskeyConfig",
    "Pbkdf2Backend",
    "ScryptBackend",
    "UnsupportedHashError",
    "Where",
    "__version__",
    "default_backend",
    "github",
    "google",
    "totp",
]
