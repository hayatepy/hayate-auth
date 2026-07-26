"""Fail-closed RFC 7662 verifier for a separated OAuth resource server."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from importlib import import_module
from typing import Any
from urllib.parse import quote_plus, urlencode, urlsplit

from .authorization_server import LOOPBACK_HOSTS, _canonical_resource
from .dpop import validate_jkt


@dataclass(frozen=True)
class OAuthIntrospectionVerifier:
    """Turn an RFC 7662 endpoint into a hayate/hayate-mcp token verifier.

    The authorization server credential is sent only with HTTP Basic over
    HTTPS (plain HTTP is accepted solely for loopback development). Network,
    protocol, and malformed-response failures all reject the access token.
    """

    endpoint: str
    client_id: str
    client_secret: str
    resource: str
    backend: Any | None = None

    def __post_init__(self) -> None:
        endpoint = urlsplit(self.endpoint)
        try:
            _endpoint_port = endpoint.port
        except ValueError:
            raise ValueError("introspection endpoint contains an invalid port") from None
        if (
            endpoint.scheme not in ("https", "http")
            or not endpoint.netloc
            or endpoint.fragment
            or endpoint.username
            or endpoint.password
        ):
            raise ValueError("introspection endpoint must be an absolute HTTP(S) URL")
        if endpoint.scheme == "http" and endpoint.hostname not in LOOPBACK_HOSTS:
            raise ValueError("introspection endpoint must use https except on loopback hosts")
        if not self.client_id:
            raise ValueError("client_id must be non-empty")
        if not self.client_secret:
            raise ValueError("client_secret must be non-empty")
        resource = urlsplit(self.resource)
        try:
            _resource_port = resource.port
        except ValueError:
            raise ValueError("resource contains an invalid port") from None
        if (
            resource.scheme not in ("https", "http")
            or not resource.netloc
            or resource.fragment
            or resource.username
            or resource.password
        ):
            raise ValueError("resource must be an absolute HTTP(S) URI without a fragment")
        if resource.scheme == "http" and resource.hostname not in LOOPBACK_HOSTS:
            raise ValueError("resource must use https except on loopback hosts")
        object.__setattr__(
            self,
            "endpoint",
            endpoint._replace(
                scheme=endpoint.scheme.lower(),
                netloc=endpoint.netloc.lower(),
            ).geturl(),
        )
        object.__setattr__(self, "resource", _canonical_resource(self.resource))

    async def __call__(self, token: str) -> dict[str, Any] | None:
        if not isinstance(token, str) or not token:
            return None
        encoded_id = quote_plus(self.client_id, safe="")
        encoded_secret = quote_plus(self.client_secret, safe="")
        credentials = base64.b64encode(f"{encoded_id}:{encoded_secret}".encode()).decode("ascii")
        hayate_fetch = import_module("hayate_fetch")
        backend = (
            self.backend
            if self.backend is not None
            else hayate_fetch.default_backend(redirect="manual")
        )
        try:
            response = await hayate_fetch.fetch(
                self.endpoint,
                method="POST",
                headers={
                    "authorization": f"Basic {credentials}",
                    "content-type": "application/x-www-form-urlencoded",
                    "accept": "application/json",
                },
                body=urlencode({"token": token, "token_type_hint": "access_token"}),
                backend=backend,
            )
            if response.status != 200:
                return None
            content_type = (response.headers.get("content-type") or "").partition(";")[0]
            if content_type.strip().lower() != "application/json":
                return None
            document = await response.json()
        except Exception:
            return None
        if not isinstance(document, dict) or document.get("active") is not True:
            return None
        audience = document.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        audience_matches = False
        for item in audiences:
            if not isinstance(item, str):
                continue
            try:
                audience_matches = _canonical_resource(item) == self.resource
            except ValueError:
                continue
            if audience_matches:
                break
        if not audience_matches:
            return None
        subject = document.get("sub")
        if not isinstance(subject, str) or not subject:
            return None
        scope = document.get("scope", "")
        if not isinstance(scope, str):
            return None
        principal: dict[str, Any] = {
            "subject": subject,
            "user_id": subject,
            "scopes": scope.split(),
            "resource": self.resource,
        }
        client_id = document.get("client_id")
        if isinstance(client_id, str):
            principal["client_id"] = client_id
        token_id = document.get("jti")
        if isinstance(token_id, str):
            principal["token_id"] = token_id
        token_type = document.get("token_type")
        confirmation = document.get("cnf")
        if token_type == "DPoP":
            if not isinstance(confirmation, dict) or not isinstance(confirmation.get("jkt"), str):
                return None
            try:
                principal["dpop_jkt"] = validate_jkt(confirmation["jkt"])
            except ValueError:
                return None
        elif confirmation is not None or token_type not in (None, "Bearer"):
            return None
        return principal
