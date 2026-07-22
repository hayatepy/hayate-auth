"""OAuth 2.1 + PKCE flow with a fake hayate-fetch backend and fake providers."""

import json
from urllib.parse import parse_qs, urlparse

import pytest
from hayate import Headers, Request, Response

from conftest import cookie_pair, request_json
from hayate_auth import Auth, OAuthProvider, ScryptBackend
from hayate_auth.adapter import Where

CALLBACK = "/api/auth/callback/testidp"
SIGNIN_SOCIAL = "/api/auth/sign-in/social"


def _provider(uses_id_token: bool = True) -> OAuthProvider:
    return OAuthProvider(
        id="testidp",
        client_id="client-abc",
        client_secret="secret-xyz",
        authorize_url="https://idp.example/authorize",
        token_url="https://idp.example/token",
        scopes="openid email profile",
        userinfo_url="https://idp.example/userinfo",
        uses_id_token=uses_id_token,
    )


def _jwt(claims: dict) -> str:
    import base64

    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{seg({'alg': 'RS256'})}.{seg(claims)}.{seg({'sig': 'unchecked'})}"


class FakeBackend:
    """Programmable FetchBackend: maps URL -> (status, json body)."""

    def __init__(self, routes: dict):
        self.routes = routes
        self.calls: list[tuple[str, dict]] = []

    async def send(self, request: Request) -> Response:
        body = await request.bytes()
        self.calls.append((request.url.href, {"body": body.decode() if body else None}))
        status, payload = self.routes[request.url.href]
        return Response(
            json.dumps(payload),
            status=status,
            headers=Headers({"content-type": "application/json"}),
        )


@pytest.fixture
def id_token_flow(adapter):
    backend = FakeBackend(
        {
            "https://idp.example/token": (
                200,
                {
                    "access_token": "at-1",
                    "id_token": _jwt(
                        {
                            "sub": "idp-user-1",
                            "email": "cloud@example.com",
                            "email_verified": True,
                            "name": "Cloud",
                        }
                    ),
                },
            )
        }
    )
    auth = Auth(
        secret="test-secret",
        adapter=adapter,
        crypto=ScryptBackend(log_n=12),
        providers=[_provider(uses_id_token=True)],
        http_backend=backend,
    )
    return auth, backend


async def _begin(auth, callback_url="/") -> tuple[str, str]:
    """Run sign-in/social; return (state, cookie header pair)."""
    res = await auth.fetch(
        request_json(SIGNIN_SOCIAL, {"provider": "testidp", "callback_url": callback_url})
    )
    assert res.status == 200
    url = (await res.json())["url"]
    query = parse_qs(urlparse(url).query)
    return query["state"][0], cookie_pair(res)


async def test_authorize_url_carries_pkce_challenge(id_token_flow):
    auth, _ = id_token_flow
    res = await auth.fetch(request_json(SIGNIN_SOCIAL, {"provider": "testidp"}))
    url = (await res.json())["url"]
    query = parse_qs(urlparse(url).query)
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] and "code_verifier" not in query
    assert query["client_id"] == ["client-abc"]


async def test_full_callback_creates_user_and_session(id_token_flow):
    auth, backend = id_token_flow
    state, cookie = await _begin(auth)

    res = await auth.fetch(
        Request(
            f"https://localhost{CALLBACK}?code=auth-code&state={state}",
            headers={"cookie": cookie},
        )
    )
    assert res.status == 302
    assert res.headers.get("location") == "/"

    # PKCE verifier was sent to the token endpoint.
    token_calls = [meta for url, meta in backend.calls if "token" in url]
    assert token_calls and "code_verifier=" in token_calls[0]["body"]

    user = await auth.adapter.find_one("user", [Where("email", "cloud@example.com")])
    assert user is not None and user["email_verified"] == 1
    account = await auth.adapter.find_one("account", [Where("provider_id", "testidp")])
    assert account["account_id"] == "idp-user-1"


async def test_second_login_reuses_the_account(id_token_flow):
    auth, _ = id_token_flow
    for _ in range(2):
        state, cookie = await _begin(auth)
        res = await auth.fetch(
            Request(f"https://localhost{CALLBACK}?code=c&state={state}", headers={"cookie": cookie})
        )
        assert res.status == 302
    accounts = await auth.adapter.find_many("account", [Where("provider_id", "testidp")])
    users = await auth.adapter.find_many("user", [])
    assert len(accounts) == 1 and len(users) == 1


async def test_state_mismatch_is_rejected(id_token_flow):
    auth, _ = id_token_flow
    _, cookie = await _begin(auth)
    res = await auth.fetch(
        Request(f"https://localhost{CALLBACK}?code=c&state=forged", headers={"cookie": cookie})
    )
    assert res.status == 400


async def test_callback_without_state_cookie_is_rejected(id_token_flow):
    auth, _ = id_token_flow
    res = await auth.fetch(Request(f"https://localhost{CALLBACK}?code=c&state=whatever"))
    assert res.status == 400


async def test_unverified_email_does_not_hijack_existing_user(adapter):
    # Seed a password user, then arrive via OAuth with the same email but
    # email_verified=false: linking must be refused (account takeover).
    backend = FakeBackend(
        {
            "https://idp.example/token": (200, {"access_token": "at"}),
            "https://idp.example/userinfo": (
                200,
                {"id": "gh-9", "email": "victim@example.com", "login": "attacker"},
            ),
        }
    )
    auth = Auth(
        secret="s",
        adapter=adapter,
        crypto=ScryptBackend(log_n=12),
        providers=[_provider(uses_id_token=False)],
        http_backend=backend,
    )
    await auth.fetch(
        request_json(
            "/api/auth/sign-up/email", {"email": "victim@example.com", "password": "long enough"}
        )
    )

    res = await auth.fetch(
        request_json(SIGNIN_SOCIAL, {"provider": "testidp", "callback_url": "/"})
    )
    state = parse_qs(urlparse((await res.json())["url"]).query)["state"][0]
    cookie = cookie_pair(res)
    cb = await auth.fetch(
        Request(f"https://localhost{CALLBACK}?code=c&state={state}", headers={"cookie": cookie})
    )
    assert cb.status == 422


async def test_open_redirect_callback_url_is_rejected(id_token_flow):
    auth, _ = id_token_flow
    res = await auth.fetch(
        request_json(
            SIGNIN_SOCIAL, {"provider": "testidp", "callback_url": "https://evil.example/x"}
        )
    )
    assert res.status == 400


async def test_unknown_provider_is_400(id_token_flow):
    auth, _ = id_token_flow
    res = await auth.fetch(request_json(SIGNIN_SOCIAL, {"provider": "nope"}))
    assert res.status == 400


async def test_token_endpoint_failure_is_502(adapter):
    backend = FakeBackend({"https://idp.example/token": (400, {"error": "invalid_grant"})})
    auth = Auth(
        secret="s",
        adapter=adapter,
        crypto=ScryptBackend(log_n=12),
        providers=[_provider(uses_id_token=True)],
        http_backend=backend,
    )
    res = await auth.fetch(request_json(SIGNIN_SOCIAL, {"provider": "testidp"}))
    state = parse_qs(urlparse((await res.json())["url"]).query)["state"][0]
    cookie = cookie_pair(res)
    cb = await auth.fetch(
        Request(f"https://localhost{CALLBACK}?code=c&state={state}", headers={"cookie": cookie})
    )
    assert cb.status == 502
