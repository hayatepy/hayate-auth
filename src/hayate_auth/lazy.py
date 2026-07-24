"""Request-aware lazy Auth registration for Cloudflare Workers bindings."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from typing import Any

from hayate import Context, Response

from .authorization_server import WELL_KNOWN_PATH

AuthFactory = Callable[[Context], Any | Awaitable[Any]]


class LazyAuth:
    """Create and cache ``Auth`` after a request makes ``c.env`` available."""

    def __init__(
        self,
        factory: AuthFactory,
        *,
        base_path: str = "/api/auth",
        authorization_server: bool = False,
        cache: bool = True,
    ) -> None:
        if not base_path.startswith("/"):
            raise ValueError("base_path must start with '/'")
        self.factory = factory
        self.base_path = base_path.rstrip("/")
        self.authorization_server = authorization_server
        self.cache = cache
        self._auth: Any | None = None
        self._lock: Any | None = None

    async def _create(self, c: Context) -> Any:
        auth = self.factory(c)
        if inspect.isawaitable(auth):
            auth = await auth
        if getattr(auth, "base_path", None) != self.base_path:
            raise ValueError(
                f"lazy auth base_path {self.base_path!r} does not match factory Auth "
                f"base_path {getattr(auth, 'base_path', None)!r}"
            )
        if self.authorization_server and auth.authorization_server is None:
            raise ValueError(
                "authorization_server=True requires the factory to return AS-mode Auth"
            )
        return auth

    async def get(self, c: Context) -> Any:
        if not self.cache:
            return await self._create(c)
        if self._auth is not None:
            return self._auth
        if self._lock is None:
            import asyncio

            self._lock = asyncio.Lock()
        async with self._lock:
            if self._auth is None:
                self._auth = await self._create(c)
        return self._auth

    async def fetch(self, c: Context) -> Response:
        auth = await self.get(c)
        response = await auth.fetch(c.req.raw)
        if not isinstance(response, Response):
            raise TypeError("lazy Auth factory returned an invalid fetch handler")
        return response

    def register(self, app: Any) -> None:
        async def auth_handler(c: Context) -> Response:
            return await self.fetch(c)

        pattern = f"{self.base_path}/*"
        app.on("GET", pattern)(auth_handler)
        app.on("POST", pattern)(auth_handler)
        if self.authorization_server:
            app.on("GET", WELL_KNOWN_PATH)(auth_handler)
