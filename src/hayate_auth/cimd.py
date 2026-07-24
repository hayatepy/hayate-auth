"""OAuth Client ID Metadata Documents for MCP authorization servers.

The client identifier is an HTTPS URL whose JSON document describes the
public OAuth client.  Fetching is injected so applications can apply their
runtime's DNS, egress, service-binding, and rate-limit policy before any
untrusted URL is requested.
"""

from __future__ import annotations

import inspect
import ipaddress
import json
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from hayate import URL, Response

from . import session as sessions
from ._uuid7 import new_id
from .adapter import Where

if TYPE_CHECKING:
    from .auth import Auth

type MetadataDocumentFetcher = Callable[[str], Awaitable[Response]]
type MetadataUrlPolicy = Callable[[str], bool | Awaitable[bool]]

MAX_DOCUMENT_BYTES = 5 * 1024
JSON_CONTENT_TYPE = re.compile(r"^application/(?:[-\w.]+\+)?json\s*(?:;|$)", re.I)
DOT_SEGMENT = re.compile(r"/\.\.?(?:/|$|[?#])")
SYMMETRIC_AUTH_METHODS = frozenset(
    {"client_secret_basic", "client_secret_post", "client_secret_jwt"}
)
ALLOWED_GRANT_TYPES = frozenset({"authorization_code", "refresh_token"})
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


@dataclass(frozen=True)
class ClientIdMetadataDocuments:
    """Enable MCP Client ID Metadata Document discovery.

    ``fetch`` must not follow redirects and should apply DNS-level SSRF
    defenses. ``allow_url`` is an additional pre-fetch hook for origin
    allowlists, rate limiting, or runtime-specific host classification.
    Responses are still type-, status-, and size-checked by hayate-auth.
    """

    fetch: MetadataDocumentFetcher
    allow_url: MetadataUrlPolicy | None = None
    refresh_ttl: timedelta = timedelta(hours=1)
    max_document_bytes: int = MAX_DOCUMENT_BYTES

    def __post_init__(self) -> None:
        if self.refresh_ttl.total_seconds() < 0:
            raise ValueError("refresh_ttl must not be negative")
        if self.max_document_bytes <= 0:
            raise ValueError("max_document_bytes must be positive")


class InvalidClientMetadata(ValueError):
    pass


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"{value} is not valid JSON")


def is_metadata_client_id(client_id: str) -> bool:
    return urlsplit(client_id).scheme == "https"


def validate_client_id_url(client_id: str) -> None:
    """Validate the URL-form client identifier before an outbound fetch."""
    if DOT_SEGMENT.search(client_id):
        raise InvalidClientMetadata("client_id URL must not contain dot segments")
    parts = urlsplit(client_id)
    if (
        parts.scheme != "https"
        or not parts.netloc
        or parts.fragment
        or parts.username
        or parts.password
    ):
        raise InvalidClientMetadata(
            "client_id must be an HTTPS URL without credentials or a fragment"
        )
    if parts.path in ("", "/"):
        raise InvalidClientMetadata("client_id URL must contain a path component")
    try:
        _port = parts.port
        host = URL(client_id).hostname.strip("[]")
    except (TypeError, ValueError):
        raise InvalidClientMetadata("client_id URL contains an invalid host or port") from None
    if host is None:
        raise InvalidClientMetadata("client_id URL must contain a host")
    if host in {"localhost", "metadata.google.internal"} or host.endswith(".localhost"):
        raise InvalidClientMetadata("client_id URL host is not a public metadata origin")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return
    if not address.is_global:
        raise InvalidClientMetadata("client_id URL must not use a private or reserved address")


def _absolute_http_uri(value: str) -> bool:
    parts = urlsplit(value)
    try:
        _port = parts.port
    except ValueError:
        return False
    return (
        parts.scheme in ("https", "http")
        and bool(parts.netloc)
        and bool(parts.hostname)
        and not parts.fragment
        and not parts.username
        and not parts.password
    )


def _same_origin_or_loopback_redirect(client_id: str, redirect_uri: str) -> bool:
    client = urlsplit(client_id)
    redirect = urlsplit(redirect_uri)
    if redirect.scheme == "http" and redirect.hostname in LOOPBACK_HOSTS:
        return True
    return (
        redirect.scheme == client.scheme
        and redirect.hostname == client.hostname
        and redirect.port == client.port
    )


def validate_metadata_document(
    client_id: str, raw: object, *, scopes_supported: tuple[str, ...]
) -> dict[str, Any]:
    """Validate and reduce an untrusted CIMD document to stored client fields."""
    if not isinstance(raw, Mapping):
        raise InvalidClientMetadata("metadata document must be a JSON object")
    data = dict(raw)
    if data.get("client_id") != client_id:
        raise InvalidClientMetadata("metadata client_id must exactly match its document URL")
    if "client_secret" in data or "client_secret_expires_at" in data:
        raise InvalidClientMetadata("metadata document must not contain client secrets")

    name = data.get("client_name")
    if not isinstance(name, str) or not name:
        raise InvalidClientMetadata("client_name must be a non-empty string")

    uris = data.get("redirect_uris")
    if (
        not isinstance(uris, list)
        or not uris
        or not all(isinstance(uri, str) and _absolute_http_uri(uri) for uri in uris)
    ):
        raise InvalidClientMetadata(
            "redirect_uris must be a non-empty array of absolute HTTP(S) URIs"
        )
    for uri in uris:
        assert isinstance(uri, str)
        redirect = urlsplit(uri)
        if redirect.scheme != "https" and not (
            redirect.scheme == "http" and redirect.hostname in LOOPBACK_HOSTS
        ):
            raise InvalidClientMetadata("redirect URIs must use HTTPS or loopback HTTP")
        if not _same_origin_or_loopback_redirect(client_id, uri):
            raise InvalidClientMetadata(
                "redirect URIs must share the client_id origin or use loopback HTTP"
            )

    method = data.get("token_endpoint_auth_method", "none")
    if method in SYMMETRIC_AUTH_METHODS:
        raise InvalidClientMetadata("CIMD clients must not use a symmetric client secret")
    if method != "none":
        # private_key_jwt can be added when the token endpoint supports its
        # assertion validation; do not advertise or silently weaken it now.
        raise InvalidClientMetadata("only token_endpoint_auth_method 'none' is supported")

    grant_types = data.get("grant_types", ["authorization_code"])
    if (
        not isinstance(grant_types, list)
        or "authorization_code" not in grant_types
        or not all(isinstance(item, str) and item in ALLOWED_GRANT_TYPES for item in grant_types)
    ):
        raise InvalidClientMetadata("unsupported grant_types")
    response_types = data.get("response_types", ["code"])
    if response_types != ["code"]:
        raise InvalidClientMetadata("only response_type 'code' is supported")

    scope = data.get("scope")
    if scope is not None:
        if not isinstance(scope, str):
            raise InvalidClientMetadata("scope must be a string")
        if scopes_supported and any(item not in scopes_supported for item in scope.split()):
            raise InvalidClientMetadata("metadata document contains an unsupported scope")

    return {
        "client_id": client_id,
        "name": name,
        "redirect_uris": uris,
        "token_endpoint_auth_method": "none",
        "grant_types": grant_types,
        "scope": scope,
    }


async def _read_limited(response: Response, maximum: int) -> bytes:
    declared = response.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > maximum:
                raise InvalidClientMetadata("metadata document exceeds the configured size limit")
        except ValueError:
            pass

    body = response.body
    if body is None:
        return b""
    if isinstance(body, bytes):
        if len(body) > maximum:
            raise InvalidClientMetadata("metadata document exceeds the configured size limit")
        return body

    chunks: list[bytes] = []
    total = 0
    async for chunk in body:
        value = bytes(chunk)
        total += len(value)
        if total > maximum:
            raise InvalidClientMetadata("metadata document exceeds the configured size limit")
        chunks.append(value)
    return b"".join(chunks)


async def _fetch_document(
    config: ClientIdMetadataDocuments,
    client_id: str,
    *,
    scopes_supported: tuple[str, ...],
) -> dict[str, Any]:
    validate_client_id_url(client_id)
    if config.allow_url is not None:
        decision = config.allow_url(client_id)
        allowed = await decision if inspect.isawaitable(decision) else decision
        if not allowed:
            raise InvalidClientMetadata("client_id URL is not permitted by the fetch policy")
    try:
        response = await config.fetch(client_id)
    except InvalidClientMetadata:
        raise
    except Exception as error:
        raise InvalidClientMetadata("metadata document fetch failed") from error
    if not response.ok:
        raise InvalidClientMetadata(f"metadata document fetch returned HTTP {response.status}")
    content_type = response.headers.get("content-type") or ""
    if not JSON_CONTENT_TYPE.match(content_type):
        raise InvalidClientMetadata("metadata document response must use a JSON content type")
    body = await _read_limited(response, config.max_document_bytes)
    try:
        decoded = json.loads(body, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, ValueError) as error:
        raise InvalidClientMetadata("metadata document is not valid JSON") from error
    return validate_metadata_document(
        client_id,
        decoded,
        scopes_supported=scopes_supported,
    )


def _is_stale(client: Mapping[str, Any], ttl: timedelta) -> bool:
    updated = client.get("updated_at") or client.get("created_at")
    if not isinstance(updated, str):
        return True
    try:
        stamp = datetime.fromisoformat(updated)
    except ValueError:
        return True
    return stamp + ttl <= sessions.now()


async def resolve_metadata_client(
    auth: Auth,
    client_id: str,
    existing: dict[str, Any] | None,
) -> dict[str, Any]:
    authorization_server = auth.authorization_server
    assert authorization_server is not None
    config = authorization_server.client_id_metadata_documents
    assert config is not None

    if existing is not None and not _is_stale(existing, config.refresh_ttl):
        return existing

    metadata = await _fetch_document(
        config,
        client_id,
        scopes_supported=authorization_server.scopes_supported,
    )
    stamp = sessions.isoformat(sessions.now())
    values = {
        "client_secret_hash": None,
        "name": metadata["name"],
        "redirect_uris": json.dumps(metadata["redirect_uris"]),
        "token_endpoint_auth_method": metadata["token_endpoint_auth_method"],
        "grant_types": json.dumps(metadata["grant_types"]),
        "scope": metadata["scope"],
        "updated_at": stamp,
    }
    if existing is not None:
        refreshed = await auth.adapter.update(
            "oauth_client",
            [Where("client_id", client_id)],
            values,
        )
        if refreshed is None:
            raise InvalidClientMetadata("client metadata record no longer exists")
        return refreshed

    try:
        return await auth.adapter.create(
            "oauth_client",
            {
                "id": new_id(),
                "client_id": client_id,
                **values,
                "created_at": stamp,
            },
        )
    except Exception:
        # Two concurrent authorization requests may discover the same client.
        # The unique client_id constraint elects one insert; use its result.
        concurrent = await auth.adapter.find_one("oauth_client", [Where("client_id", client_id)])
        if concurrent is None:
            raise
        return concurrent
