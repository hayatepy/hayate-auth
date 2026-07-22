"""Opaque session tokens (DESIGN §6).

The cookie carries ``secrets.token_urlsafe(32)``; the database stores only
its SHA-256, so a leaked database cannot impersonate anyone. Cookie name is
``__Host-hayate_auth.session`` on HTTPS and falls back to the bare name for
local plain-HTTP development.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from hayate import Request
from hayate.cookies import parse_cookies, serialize_set_cookie

from ._uuid7 import new_id
from .adapter import Adapter, Where

COOKIE_BASE = "hayate_auth.session"
HOST_COOKIE = f"__Host-{COOKIE_BASE}"


def now() -> datetime:
    return datetime.now(UTC)


def isoformat(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds")


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def is_secure_request(request: Request) -> bool:
    return request.url.protocol == "https:"


def read_token(request: Request) -> str | None:
    header = request.headers.get("cookie")
    if header is None:
        return None
    cookies = parse_cookies(header)
    return cookies.get(HOST_COOKIE) or cookies.get(COOKIE_BASE)


def session_cookie(token: str, *, secure: bool, max_age: int) -> str:
    return serialize_set_cookie(
        HOST_COOKIE if secure else COOKIE_BASE,
        token,
        max_age=max_age,
        path="/",
        secure=secure,
        http_only=True,
        same_site="lax",
    )


def clear_cookie(*, secure: bool) -> str:
    return serialize_set_cookie(
        HOST_COOKIE if secure else COOKIE_BASE,
        "",
        max_age=0,
        path="/",
        secure=secure,
        http_only=True,
        same_site="lax",
    )


async def create_session(
    adapter: Adapter, user_id: str, *, ttl: timedelta, user_agent: str | None
) -> tuple[str, dict[str, Any]]:
    """Insert a session row and return (cookie token, public row)."""
    token = new_token()
    record = {
        "id": new_id(),
        "token_hash": token_hash(token),
        "user_id": user_id,
        "expires_at": isoformat(now() + ttl),
        "ip_address": None,
        "user_agent": user_agent,
        "created_at": isoformat(now()),
    }
    await adapter.create("session", record)
    return token, record


async def resolve_session(adapter: Adapter, request: Request) -> dict[str, Any] | None:
    """The session row for the request's cookie, or None. Expired rows are
    deleted on sight."""
    token = read_token(request)
    if token is None:
        return None
    record = await adapter.find_one("session", [Where("token_hash", token_hash(token))])
    if record is None:
        return None
    if record["expires_at"] <= isoformat(now()):
        await adapter.delete("session", [Where("id", record["id"])])
        return None
    return record


async def revoke_session(adapter: Adapter, request: Request) -> None:
    token = read_token(request)
    if token is not None:
        await adapter.delete("session", [Where("token_hash", token_hash(token))])


def public_session(record: dict[str, Any]) -> dict[str, Any]:
    """The wire shape: everything except the token hash."""
    return {key: value for key, value in record.items() if key != "token_hash"}
