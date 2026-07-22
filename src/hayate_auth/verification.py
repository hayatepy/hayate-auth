"""One-shot verification tokens (DESIGN §2: the explicit non-standard part).

Same storage discipline as sessions: the mail carries an opaque
``secrets.token_urlsafe(32)``, the database keeps only its SHA-256, rows
expire and are consumed on first use.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from ._uuid7 import new_id
from .adapter import Adapter, Where
from .session import isoformat, new_token, now, token_hash


async def create_verification(adapter: Adapter, identifier: str, *, ttl: timedelta) -> str:
    """Insert a verification row and return the raw token (for the email)."""
    token = new_token()
    await adapter.create(
        "verification",
        {
            "id": new_id(),
            "identifier": identifier,
            "value_hash": token_hash(token),
            "expires_at": isoformat(now() + ttl),
            "created_at": isoformat(now()),
        },
    )
    return token


async def consume_verification(
    adapter: Adapter, token: str, *, prefix: str
) -> dict[str, Any] | None:
    """Find, validate, and delete the row for ``token``; return it, or None.

    ``prefix`` guards token confusion: a reset token can never pass as an
    email-verification token and vice versa.
    """
    row = await adapter.find_one("verification", [Where("value_hash", token_hash(token))])
    if row is None or not row["identifier"].startswith(prefix):
        return None
    await adapter.delete("verification", [Where("id", row["id"])])
    if row["expires_at"] <= isoformat(now()):
        return None
    return row
