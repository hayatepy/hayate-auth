import base64
import json
from urllib.parse import parse_qs

import hayate_fetch
import pytest
from hayate import Response

from hayate_auth import OAuthIntrospectionVerifier


class Backend:
    def __init__(self, response: Response) -> None:
        self.response = response
        self.requests = []

    async def send(self, request):
        self.requests.append(request)
        return self.response


async def test_separated_resource_server_verifier_returns_mcp_claims():
    backend = Backend(
        Response(
            json.dumps(
                {
                    "active": True,
                    "sub": "user-1",
                    "client_id": "oauth-client",
                    "scope": "mcp tools:call",
                    "aud": "https://mcp.example/mcp",
                    "jti": "token-1",
                }
            ),
            headers={"content-type": "application/json"},
        )
    )
    verifier = OAuthIntrospectionVerifier(
        endpoint="https://auth.example/api/auth/oauth2/introspect",
        client_id="mcp-rs",
        client_secret="resource-secret",
        resource="https://mcp.example/mcp",
        backend=backend,
    )
    claims = await verifier("hat_token")
    assert claims == {
        "subject": "user-1",
        "user_id": "user-1",
        "scopes": ["mcp", "tools:call"],
        "resource": "https://mcp.example/mcp",
        "client_id": "oauth-client",
        "token_id": "token-1",
    }
    request = backend.requests[0]
    assert request.method == "POST"
    credentials = request.headers.get("authorization").removeprefix("Basic ")
    assert base64.b64decode(credentials).decode() == "mcp-rs:resource-secret"
    assert parse_qs(await request.text()) == {
        "token": ["hat_token"],
        "token_type_hint": ["access_token"],
    }


async def test_separated_verifier_preserves_dpop_confirmation_for_request_validation():
    jkt = "A" * 43
    backend = Backend(
        Response(
            json.dumps(
                {
                    "active": True,
                    "sub": "user-1",
                    "aud": "https://mcp.example/mcp",
                    "token_type": "DPoP",
                    "cnf": {"jkt": jkt},
                }
            ),
            headers={"content-type": "application/json"},
        )
    )
    verifier = OAuthIntrospectionVerifier(
        endpoint="https://auth.example/introspect",
        client_id="mcp-rs",
        client_secret="secret",
        resource="https://mcp.example/mcp",
        backend=backend,
    )
    claims = await verifier("hat_token")
    assert claims is not None
    assert claims["dpop_jkt"] == jkt

    backend.response = Response(
        json.dumps(
            {
                "active": True,
                "sub": "user-1",
                "aud": "https://mcp.example/mcp",
                "token_type": "DPoP",
            }
        ),
        headers={"content-type": "application/json"},
    )
    assert await verifier("hat_token") is None


@pytest.mark.parametrize(
    "response",
    [
        Response('{"active":false}', headers={"content-type": "application/json"}),
        Response(
            '{"active":true,"sub":"u","aud":"https://other.example/mcp"}',
            headers={"content-type": "application/json"},
        ),
        Response(
            '{"active":true,"sub":"u","aud":"https://[invalid/mcp"}',
            headers={"content-type": "application/json"},
        ),
        Response("not-json", headers={"content-type": "application/json"}),
        Response('{"active":true}', status=401, headers={"content-type": "application/json"}),
        Response('{"active":true}', headers={"content-type": "text/plain"}),
    ],
)
async def test_separated_verifier_fails_closed(response):
    verifier = OAuthIntrospectionVerifier(
        endpoint="https://auth.example/introspect",
        client_id="mcp-rs",
        client_secret="secret",
        resource="https://mcp.example/mcp",
        backend=Backend(response),
    )
    assert await verifier("hat_token") is None


async def test_separated_verifier_refuses_redirects_by_default(monkeypatch):
    backend = Backend(Response('{"active":false}', headers={"content-type": "application/json"}))
    redirects = []

    def default_backend(*, redirect):
        redirects.append(redirect)
        return backend

    monkeypatch.setattr(hayate_fetch, "default_backend", default_backend)
    verifier = OAuthIntrospectionVerifier(
        endpoint="https://auth.example/introspect",
        client_id="mcp-rs",
        client_secret="secret",
        resource="https://mcp.example/mcp",
    )
    assert await verifier("hat_token") is None
    assert redirects == ["manual"]
    assert len(backend.requests) == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("endpoint", "http://auth.example/introspect"),
        ("endpoint", "not-a-url"),
        ("resource", "http://mcp.example/mcp"),
        ("resource", "not-a-url"),
        ("client_id", ""),
        ("client_secret", ""),
    ],
)
def test_separated_verifier_rejects_unsafe_configuration(field, value):
    config = {
        "endpoint": "https://auth.example/introspect",
        "client_id": "mcp-rs",
        "client_secret": "secret",
        "resource": "https://mcp.example/mcp",
        field: value,
    }
    with pytest.raises(ValueError):
        OAuthIntrospectionVerifier(**config)
