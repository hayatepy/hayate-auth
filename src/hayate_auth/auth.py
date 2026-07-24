"""The Auth core: one pure function, ``fetch(Request) -> Response``
(DESIGN §3), plus the three sugar helpers an app actually touches.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from hayate import Context, HTTPException, Middleware, Next, Request, Response, problem

from . import csrf
from . import session as sessions
from .adapter import Adapter, Where
from .authorization_server import WELL_KNOWN_PATH
from .crypto import CryptoBackend, default_backend
from .principal import bearer_middleware
from .routes import ROUTES, public_user


class Auth:
    def __init__(
        self,
        *,
        secret: str,
        adapter: Adapter,
        crypto: CryptoBackend | None = None,
        base_path: str = "/api/auth",
        trusted_origins: tuple[str, ...] | list[str] = (),
        session_ttl: timedelta = timedelta(days=7),
        verification_ttl: timedelta = timedelta(hours=1),
        send_reset_password: Any | None = None,
        send_verification_email: Any | None = None,
        providers: list[Any] | tuple[Any, ...] = (),
        http_backend: Any | None = None,
        totp_issuer: str = "hayate-auth",
        authorization_server: Any | None = None,
        plugins: list[Any] | tuple[Any, ...] = (),
        passkey: Any | None = None,
    ) -> None:
        if not secret:
            raise ValueError("secret must be a non-empty string")
        if not base_path.startswith("/"):
            raise ValueError("base_path must start with '/'")
        self.secret = secret
        self.adapter = adapter
        self.crypto = crypto if crypto is not None else default_backend()
        self.base_path = base_path.rstrip("/")
        self.trusted_origins = frozenset(trusted_origins)
        self.session_ttl = session_ttl
        self.verification_ttl = verification_ttl
        # App-owned delivery callbacks: async (public_user, token) -> None.
        # The app builds the link and sends the mail; the core only mints
        # and checks tokens (DESIGN §10).
        self.send_reset_password = send_reset_password
        self.send_verification_email = send_verification_email
        # OAuth (v0.3): registered providers by id, and the hayate-fetch
        # backend override (tests inject a fake; None = runtime default).
        self.providers = {provider.id: provider for provider in providers}
        self.http_backend = http_backend
        self.totp_issuer = totp_issuer
        # AS mode (v0.6): an AuthorizationServer config, or None. When set,
        # the OAuth 2.1 endpoints and the RFC 8414 well-known route go live.
        self.authorization_server = authorization_server
        if authorization_server is not None and not callable(getattr(adapter, "update_many", None)):
            raise TypeError(
                "authorization-server mode requires an adapter with atomic update_many()"
            )
        # Passkeys (v0.7): a PasskeyConfig, or None -> routes answer 404.
        self.passkey = passkey
        # Route table = built-ins + built-in plugins + user plugins
        # (DESIGN §20.2). A collision is a construction-time error.
        from .api_key import PLUGIN as api_key_plugin

        self._routes = dict(ROUTES)
        for plugin in (api_key_plugin, *plugins):
            for key, handler in plugin.routes.items():
                if key in self._routes:
                    raise ValueError(f"plugin {plugin.id!r} redefines route {key[0]} {key[1]}")
                self._routes[key] = handler
        self._dummy: str | None = None

    # -- the core ----------------------------------------------------------------------

    async def fetch(self, request: Request) -> Response:
        """Serve one auth API request. I/O happens only through the injected
        protocols, so tests call this directly with a bare Request."""
        raw = getattr(request, "raw", request)
        path = raw.url.pathname
        if self.authorization_server is not None and path == WELL_KNOWN_PATH:
            if raw.method != "GET":
                return problem(405, title="Method Not Allowed")
            from .authorization_server import well_known

            return well_known(self)
        if path != self.base_path and not path.startswith(self.base_path + "/"):
            return problem(404, title="Not Found")
        sub = path[len(self.base_path) :]

        if raw.method == "POST" and not csrf.is_allowed(raw, self.trusted_origins):
            return problem(403, title="Cross-origin request rejected")

        if raw.method == "GET" and sub.startswith("/callback/"):
            from .oauth import oauth_callback

            return await oauth_callback(self, raw, sub.removeprefix("/callback/"))

        handler = self._routes.get((raw.method, sub))
        if handler is None:
            return problem(404, title="Not Found")
        response = await handler(self, raw)
        if not isinstance(response, Response):
            raise TypeError("auth route handlers must return Response")
        return response

    # -- sugar -------------------------------------------------------------------------

    def register(self, app: Any) -> None:
        """Mount the auth API: two catch-all routes, nothing else
        (better-auth's Hono recipe, DESIGN §3.2)."""

        async def auth_handler(c: Context) -> Response:
            return await self.fetch(c.req.raw)

        pattern = f"{self.base_path}/*"
        app.on("GET", pattern)(auth_handler)
        app.on("POST", pattern)(auth_handler)
        if self.authorization_server is not None:
            # RFC 8414 pins the metadata document to the issuer root, outside
            # base_path — the one extra route AS mode needs (DESIGN §19.3).
            app.on("GET", WELL_KNOWN_PATH)(auth_handler)

    def require_session(self) -> Middleware:
        """Middleware: 401 Problem Details unless a valid session cookie is
        presented; on success ``c.get("user")`` / ``c.get("session")`` are set."""

        async def require_session_middleware(c: Context, next_: Next) -> None:
            resolved = await self.get_session(c.req.raw)
            if resolved is None:
                raise HTTPException(401, title="Authentication required")
            user, record = resolved
            c.set("user", user)
            c.set("session", record)
            c.set(
                "principal",
                {
                    "subject": user["id"],
                    "user_id": user["id"],
                    "scopes": [],
                    "credential_type": "session",
                },
            )
            await next_()

        require_session_middleware.__openapi_security__ = [  # type: ignore[attr-defined]
            {"SessionCookie": []}
        ]
        return require_session_middleware

    def require_api_key(self, *required_scopes: str) -> Middleware:
        """Require a Bearer API key and expose ``c.get("principal")``."""
        return bearer_middleware(
            self.verify_api_key,
            required_scopes=required_scopes,
            credential_type="api_key",
            scheme_name="ApiKeyBearer",
        )

    def require_oauth_token(self, *required_scopes: str, resource: str | None = None) -> Middleware:
        """Require an AS-mode Bearer token, optional resource, and scopes."""
        return bearer_middleware(
            self.oauth_token_verifier(resource=resource),
            required_scopes=required_scopes,
            credential_type="oauth",
            scheme_name="OAuth2",
        )

    async def get_session(self, request: Request) -> tuple[dict[str, Any], dict[str, Any]] | None:
        """(public user, public session) for the request's cookie, or None."""
        raw = getattr(request, "raw", request)
        record = await sessions.resolve_session(self.adapter, raw)
        if record is None:
            return None
        user_row = await self.adapter.find_one("user", [Where("id", record["user_id"])])
        if user_row is None:
            return None
        return public_user(user_row), sessions.public_session(record)

    async def verify_api_key(self, key: str) -> dict[str, Any] | None:
        """Verify an API key, returning ``{user_id, scopes, key_id, name}`` or
        None. Drop this straight into hayate-mcp's
        ``Authorization(verify_token=auth.verify_api_key)``."""
        from .api_key import verify_key

        return await verify_key(self, key)

    async def verify_oauth_token(
        self, token: str, *, resource: str | None = None
    ) -> dict[str, Any] | None:
        """Verify an AS-mode access token, returning
        ``{user_id, client_id, scopes, token_id, resource}`` or None. With
        ``resource`` set, tokens minted for another RFC 8707 resource fail."""
        from .authorization_server import verify_token

        return await verify_token(self, token, resource=resource)

    def oauth_token_verifier(self, *, resource: str | None = None) -> Any:
        """A ``verify_token`` callable with the RFC 8707 resource bound —
        made for hayate-mcp:
        ``Authorization(verify_token=auth.oauth_token_verifier(resource=...))``."""

        async def verify(token: str) -> dict[str, Any] | None:
            return await self.verify_oauth_token(token, resource=resource)

        return verify

    def openapi_security_schemes(self) -> dict[str, dict[str, Any]]:
        """Security schemes matching ``require_*`` middleware annotations."""
        from .session import HOST_COOKIE

        schemes: dict[str, dict[str, Any]] = {
            "SessionCookie": {
                "type": "apiKey",
                "in": "cookie",
                "name": HOST_COOKIE,
            },
            "ApiKeyBearer": {
                "type": "http",
                "scheme": "bearer",
                "description": "hayate-auth API key",
            },
        }
        config = self.authorization_server
        if config is not None:
            base = config.issuer + self.base_path
            schemes["OAuth2"] = {
                "type": "oauth2",
                "flows": {
                    "authorizationCode": {
                        "authorizationUrl": f"{base}/oauth2/authorize",
                        "tokenUrl": f"{base}/oauth2/token",
                        "scopes": {scope: scope for scope in config.scopes_supported},
                    }
                },
            }
        return schemes

    # -- internals ---------------------------------------------------------------------

    async def _dummy_hash(self) -> str:
        """A throwaway hash used to equalize sign-in timing for unknown
        users. Generated once per Auth instance, lazily."""
        if self._dummy is None:
            self._dummy = await self.crypto.hash_password("hayate-auth-timing-dummy")
        return self._dummy
