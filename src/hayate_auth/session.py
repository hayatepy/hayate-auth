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
    moment = now()
    stamp = isoformat(moment)
    record = {
        "id": new_id(),
        "token_hash": token_hash(token),
        "user_id": user_id,
        "expires_at": isoformat(moment + ttl),
        "ip_address": None,
        "user_agent": user_agent,
        "last_active_at": stamp,
        "created_at": stamp,
    }
    await adapter.create("session", record)
    return token, record


def _last_active(record: dict[str, Any]) -> str:
    # The fallback makes a rolling upgrade safe between applying the migration
    # and restarting every application instance.
    value = record.get("last_active_at") or record["created_at"]
    if not isinstance(value, str):
        raise TypeError("session activity timestamp must be a string")
    return value


def is_expired(
    record: dict[str, Any],
    *,
    moment: datetime,
    idle_timeout: timedelta | None,
) -> bool:
    stamp = isoformat(moment)
    if record["expires_at"] <= stamp:
        return True
    return idle_timeout is not None and _last_active(record) <= isoformat(moment - idle_timeout)


async def resolve_session(
    adapter: Adapter,
    request: Request,
    *,
    idle_timeout: timedelta | None,
    touch_interval: timedelta,
) -> dict[str, Any] | None:
    """Resolve, expire, and sparsely touch the request's opaque session.

    Touches use an atomic compare-and-swap. Concurrent requests therefore
    produce at most one write per interval, and a concurrent revocation wins
    because a failed CAS is followed by an authoritative re-read.
    """
    token = read_token(request)
    if token is None:
        return None
    digest = token_hash(token)
    record = await adapter.find_one("session", [Where("token_hash", digest)])
    if record is None:
        return None
    moment = now()
    if is_expired(record, moment=moment, idle_timeout=idle_timeout):
        await adapter.delete(
            "session",
            [Where("id", record["id"]), Where("token_hash", digest)],
        )
        return None

    previous_activity = _last_active(record)
    if previous_activity <= isoformat(moment - touch_interval):
        stamp = isoformat(moment)
        touched = await adapter.update_many(
            "session",
            [
                Where("id", record["id"]),
                Where("token_hash", digest),
                Where("last_active_at", previous_activity),
            ],
            {"last_active_at": stamp},
        )
        if touched == 1:
            record["last_active_at"] = stamp
        else:
            record = await adapter.find_one("session", [Where("token_hash", digest)])
            if record is None or is_expired(
                record,
                moment=moment,
                idle_timeout=idle_timeout,
            ):
                return None
    return record


async def revoke_session(adapter: Adapter, request: Request) -> None:
    token = read_token(request)
    if token is not None:
        await adapter.delete("session", [Where("token_hash", token_hash(token))])


async def list_active_sessions(
    adapter: Adapter,
    user_id: str,
    *,
    idle_timeout: timedelta | None,
) -> list[dict[str, Any]]:
    """Return active rows without mutating them or exposing token digests."""
    moment = now()
    records = await adapter.find_many(
        "session",
        [Where("user_id", user_id)],
        sort=("last_active_at", "desc"),
    )
    return [
        public_session(record)
        for record in records
        if not is_expired(record, moment=moment, idle_timeout=idle_timeout)
    ]


async def revoke_user_session(adapter: Adapter, user_id: str, session_id: str) -> int:
    """Delete one owned session without disclosing whether it existed."""
    return await adapter.delete(
        "session",
        [Where("id", session_id), Where("user_id", user_id)],
    )


async def revoke_user_sessions(
    adapter: Adapter,
    user_id: str,
    *,
    except_session_id: str | None = None,
) -> int:
    """Administrative primitive for all or all-but-one user sessions."""
    where = [Where("user_id", user_id)]
    if except_session_id is not None:
        where.append(Where("id", except_session_id, "ne"))
    return await adapter.delete("session", where)


def public_session(record: dict[str, Any]) -> dict[str, Any]:
    """The wire shape: everything except the token hash."""
    return {key: value for key, value in record.items() if key != "token_hash"}
