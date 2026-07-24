"""hayate-auth: authentication for hayate as a pure fetch handler."""

from . import totp
from .adapter import Adapter, Where
from .auth import Auth
from .authorization_server import AuthorizationServer
from .cimd import ClientIdMetadataDocuments
from .crypto import (
    CryptoBackend,
    Pbkdf2Backend,
    ScryptBackend,
    UnsupportedHashError,
    default_backend,
)
from .lazy import LazyAuth
from .oauth import OAuthProvider, github, google
from .passkey import PasskeyConfig
from .plugin import AuthPlugin
from .principal import Principal

__version__ = "0.8.0"

__all__ = [
    "Adapter",
    "Auth",
    "AuthPlugin",
    "AuthorizationServer",
    "ClientIdMetadataDocuments",
    "CryptoBackend",
    "LazyAuth",
    "OAuthProvider",
    "PasskeyConfig",
    "Pbkdf2Backend",
    "Principal",
    "ScryptBackend",
    "UnsupportedHashError",
    "Where",
    "__version__",
    "default_backend",
    "github",
    "google",
    "totp",
]
