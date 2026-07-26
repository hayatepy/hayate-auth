"""hayate-auth: authentication for hayate as a pure fetch handler."""

from . import totp
from .adapter import Adapter, Where
from .auth import Auth
from .authorization_server import AuthorizationServer, OAuthResourceServer
from .cimd import ClientIdMetadataDocuments
from .crypto import (
    CryptoBackend,
    Pbkdf2Backend,
    ScryptBackend,
    UnsupportedHashError,
    default_backend,
)
from .introspection import OAuthIntrospectionVerifier
from .lazy import LazyAuth
from .oauth import OAuthProvider, github, google
from .passkey import PasskeyConfig
from .password import (
    COMMON_PASSWORDS,
    CompromisedPasswordChecker,
    PasswordPolicy,
    PasswordPolicyUnavailable,
)
from .plugin import AuthPlugin
from .principal import Principal

__version__ = "0.9.1"

__all__ = [
    "COMMON_PASSWORDS",
    "Adapter",
    "Auth",
    "AuthPlugin",
    "AuthorizationServer",
    "ClientIdMetadataDocuments",
    "CompromisedPasswordChecker",
    "CryptoBackend",
    "LazyAuth",
    "OAuthIntrospectionVerifier",
    "OAuthProvider",
    "OAuthResourceServer",
    "PasskeyConfig",
    "PasswordPolicy",
    "PasswordPolicyUnavailable",
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
