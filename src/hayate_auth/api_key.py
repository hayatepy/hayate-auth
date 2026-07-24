"""API keys (better-auth's API Key plugin, adapted to house style; DESIGN §7).

A key is ``ha_<token>``; only its SHA-256 is stored (same discipline as
sessions), with a short display prefix kept for listings. Verification hashes
the presented key and looks it up by that hash — O(1), no secret at rest.

``Auth.verify_api_key(key)`` returns the identity, so it drops straight into
hayate-mcp's ``Authorization(verify_token=...)``: an API key protects an MCP
server with one line.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from hayate import Request, Response, problem

from . import session as sessions
from ._uuid7 import new_id
from .adapter import Where
from .plugin import AuthPlugin
from .principal import principal_from_claims
from .routes import _json_response, _read_json_object

if TYPE_CHECKING:
    from .auth import Auth

KEY_PREFIX = "ha_"
PREFIX_DISPLAY_LEN = 11  # "ha_" + 8 chars, shown in listings for identification


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("ascii")).hexdigest()


def _public_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "prefix": row["prefix"],
        "scopes": json.loads(row["scopes"]) if row["scopes"] else [],
        "expires_at": row["expires_at"],
        "enabled": bool(row["enabled"]),
        "last_used_at": row["last_used_at"],
        "created_at": row["created_at"],
    }


async def _require_user(auth: Auth, request: Request) -> dict[str, Any] | Response:
    resolved = await auth.get_session(request)
    if resolved is None:
        return problem(401, title="Authentication required")
    return resolved[0]


async def create(auth: Auth, request: Request) -> Response:
    """Mint a key for the signed-in user. The secret is returned exactly once."""
    user = await _require_user(auth, request)
    if isinstance(user, Response):
        return user
    data = await _read_json_object(request)
    if isinstance(data, Response):
        return data

    name = data.get("name")
    if name is not None and not isinstance(name, str):
        return problem(400, title="Name must be a string")
    scopes = data.get("scopes")
    if scopes is not None and not (
        isinstance(scopes, list) and all(isinstance(s, str) for s in scopes)
    ):
        return problem(400, title="Scopes must be a list of strings")
    expires_at = None
    if (seconds := data.get("expires_in")) is not None:
        if not isinstance(seconds, int) or seconds <= 0:
            return problem(400, title="expires_in must be a positive integer (seconds)")
        expires_at = sessions.isoformat(sessions.now() + timedelta(seconds=seconds))

    key = KEY_PREFIX + secrets.token_urlsafe(32)
    stamp = sessions.isoformat(sessions.now())
    row = {
        "id": new_id(),
        "user_id": user["id"],
        "name": name,
        "prefix": key[:PREFIX_DISPLAY_LEN],
        "key_hash": _hash_key(key),
        "scopes": json.dumps(scopes) if scopes else None,
        "expires_at": expires_at,
        "enabled": 1,
        "last_used_at": None,
        "created_at": stamp,
        "updated_at": stamp,
    }
    await auth.adapter.create("api_key", row)
    # ``key`` appears here and never again.
    return _json_response({"key": key, **_public_row(row)}, status=201)


async def verify(auth: Auth, request: Request) -> Response:
    """Public endpoint: check a key, return validity + identity (no secret)."""
    data = await _read_json_object(request)
    if isinstance(data, Response):
        return data
    claims = await auth.verify_api_key(str(data.get("key", "")))
    if claims is None:
        return _json_response({"valid": False}, status=401)
    return _json_response({"valid": True, **claims})


async def list_keys(auth: Auth, request: Request) -> Response:
    user = await _require_user(auth, request)
    if isinstance(user, Response):
        return user
    rows = await auth.adapter.find_many(
        "api_key", [Where("user_id", user["id"])], sort=("created_at", "desc")
    )
    return _json_response({"keys": [_public_row(r) for r in rows]})


async def delete(auth: Auth, request: Request) -> Response:
    user = await _require_user(auth, request)
    if isinstance(user, Response):
        return user
    data = await _read_json_object(request)
    if isinstance(data, Response):
        return data
    key_id = data.get("id")
    if not isinstance(key_id, str):
        return problem(400, title="id is required")
    removed = await auth.adapter.delete(
        "api_key", [Where("id", key_id), Where("user_id", user["id"])]
    )
    if not removed:
        return problem(404, title="API key not found")
    return _json_response({"success": True})


async def verify_key(auth: Auth, key: str) -> dict[str, Any] | None:
    """The core check, shared by the endpoint and ``Auth.verify_api_key``.

    Returns ``{user_id, scopes, key_id, name}`` for a live key, else None.
    Touches ``last_used_at`` on success and purges an expired key on sight.
    """
    if not key.startswith(KEY_PREFIX):
        return None
    row = await auth.adapter.find_one("api_key", [Where("key_hash", _hash_key(key))])
    if row is None or not row["enabled"]:
        return None
    if row["expires_at"] is not None and row["expires_at"] <= sessions.isoformat(sessions.now()):
        await auth.adapter.delete("api_key", [Where("id", row["id"])])
        return None
    await auth.adapter.update(
        "api_key",
        [Where("id", row["id"])],
        {"last_used_at": sessions.isoformat(sessions.now())},
    )
    return principal_from_claims(
        {
            "user_id": row["user_id"],
            "scopes": json.loads(row["scopes"]) if row["scopes"] else [],
            "key_id": row["id"],
            "name": row["name"],
        },
        credential_type="api_key",
    )


# The API-key endpoints ship as a built-in plugin: the first migration of
# existing code onto the AuthPlugin surface (DESIGN §20.2). Paths, schema,
# and ``Auth.verify_api_key`` are unchanged.
PLUGIN = AuthPlugin(
    id="api-key",
    routes={
        ("POST", "/api-key/create"): create,
        ("POST", "/api-key/verify"): verify,
        ("GET", "/api-key/list"): list_keys,
        ("POST", "/api-key/delete"): delete,
    },
)
