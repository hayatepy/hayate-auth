"""Shared authenticated-principal shape and Bearer helpers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Literal, cast

from hayate import Context, HTTPException, Middleware, Next

type Principal = dict[str, Any]


TokenVerifier = Callable[[str], Awaitable[dict[str, Any] | None]]


def principal_from_claims(
    claims: dict[str, Any], *, credential_type: Literal["api_key", "oauth"]
) -> Principal:
    principal = dict(claims)
    subject = principal.get("subject") or principal.get("sub") or principal.get("user_id")
    if not isinstance(subject, str) or not subject:
        raise ValueError("verified token claims must contain subject, sub, or user_id")
    scopes = principal.get("scopes", [])
    if isinstance(scopes, str):
        scopes = scopes.split()
    if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
        raise ValueError("verified token claims scopes must be a string or list of strings")
    principal["subject"] = subject
    principal["scopes"] = scopes
    principal["credential_type"] = credential_type
    return principal


def bearer_middleware(
    verify_token: TokenVerifier,
    *,
    required_scopes: Sequence[str] = (),
    credential_type: Literal["api_key", "oauth"],
    scheme_name: str,
) -> Middleware:
    """Require a Bearer credential and place its Principal on the context."""

    required = tuple(dict.fromkeys(required_scopes))
    advertised_scope = " ".join(required)

    async def require_bearer(c: Context, next_: Next) -> None:
        header = c.req.headers.get("authorization")
        scheme, separator, token = (header or "").partition(" ")
        token = token.strip()
        if (
            not separator
            or scheme.lower() != "bearer"
            or not token
            or any(character.isspace() for character in token)
        ):
            raise HTTPException(
                401,
                title="Authentication required",
                headers={"www-authenticate": "Bearer"},
            )
        claims = await verify_token(token)
        if claims is None:
            raise HTTPException(
                401,
                title="Invalid access token",
                headers={"www-authenticate": 'Bearer error="invalid_token"'},
            )
        principal = principal_from_claims(claims, credential_type=credential_type)
        missing = [scope for scope in required if scope not in principal["scopes"]]
        if missing:
            challenge = 'Bearer error="insufficient_scope"'
            if advertised_scope:
                challenge += f', scope="{advertised_scope}"'
            raise HTTPException(
                403,
                title="Insufficient scope",
                headers={"www-authenticate": challenge},
                extensions={"required_scopes": list(required)},
            )
        c.set("principal", principal)
        await next_()

    # hayate-openapi reads this optional, framework-neutral annotation.
    metadata_target = cast(Any, require_bearer)
    metadata_target.__openapi_security__ = [{scheme_name: list(required)}]
    return require_bearer
