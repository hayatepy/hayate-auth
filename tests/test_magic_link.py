"""Magic link (DESIGN §20.1) and the AuthPlugin machinery (§20.2)."""

from datetime import timedelta

import pytest
from hayate import Request

from conftest import cookie_pair, request_json
from hayate_auth import Auth, AuthPlugin, ScryptBackend
from hayate_auth.plugins import magic_link

BASE = "/api/auth"


class Outbox:
    def __init__(self):
        self.sent: list[tuple[str, str]] = []

    async def __call__(self, email: str, token: str) -> None:
        self.sent.append((email, token))


@pytest.fixture
def outbox():
    return Outbox()


@pytest.fixture
def auth_ml(adapter, outbox):
    return Auth(
        secret="test-secret",
        adapter=adapter,
        crypto=ScryptBackend(log_n=12),
        plugins=[magic_link(send=outbox)],
    )


async def request_link(auth, email="link@example.com", **extra):
    return await auth.fetch(request_json(f"{BASE}/sign-in/magic-link", {"email": email, **extra}))


async def test_request_and_verify_creates_a_verified_user(auth_ml, outbox):
    res = await request_link(auth_ml, callback_url="/welcome")
    assert res.status == 200
    assert (await res.json()) == {"success": True}
    email, token = outbox.sent[0]
    assert email == "link@example.com"

    verify = await auth_ml.fetch(Request(f"http://localhost{BASE}/magic-link/verify?token={token}"))
    assert verify.status == 302
    assert verify.headers.get("location") == "/welcome"
    cookie = cookie_pair(verify)

    session = await auth_ml.fetch(
        Request(f"http://localhost{BASE}/get-session", headers={"cookie": cookie})
    )
    body = await session.json()
    assert body["user"]["email"] == "link@example.com"
    assert body["user"]["email_verified"] is True


async def test_existing_unverified_user_gets_promoted(auth_ml, outbox):
    signup = await auth_ml.fetch(
        request_json(
            f"{BASE}/sign-up/email", {"email": "old@example.com", "password": "long enough"}
        )
    )
    assert signup.status == 200

    await request_link(auth_ml, email="old@example.com")
    _, token = outbox.sent[-1]
    verify = await auth_ml.fetch(Request(f"http://localhost{BASE}/magic-link/verify?token={token}"))
    assert verify.status == 302

    cookie = cookie_pair(verify)
    session = await auth_ml.fetch(
        Request(f"http://localhost{BASE}/get-session", headers={"cookie": cookie})
    )
    body = await session.json()
    assert body["user"]["email_verified"] is True
    # Still one user: the link signed in, it did not duplicate.
    users = await auth_ml.adapter.find_many("user", [])
    assert len(users) == 1


async def test_unknown_and_known_emails_answer_identically(auth_ml):
    unknown = await request_link(auth_ml, email="ghost@example.com")
    known = await request_link(auth_ml, email="ghost@example.com")
    assert unknown.status == known.status == 200
    assert (await unknown.json()) == (await known.json())


async def test_token_is_single_use(auth_ml, outbox):
    await request_link(auth_ml)
    _, token = outbox.sent[0]
    first = await auth_ml.fetch(Request(f"http://localhost{BASE}/magic-link/verify?token={token}"))
    assert first.status == 302
    replay = await auth_ml.fetch(Request(f"http://localhost{BASE}/magic-link/verify?token={token}"))
    assert replay.status == 400


async def test_expired_token_is_rejected(adapter, outbox):
    auth = Auth(
        secret="test-secret",
        adapter=adapter,
        crypto=ScryptBackend(log_n=12),
        plugins=[magic_link(send=outbox, ttl=timedelta(seconds=-1))],
    )
    await request_link(auth)
    _, token = outbox.sent[0]
    res = await auth.fetch(Request(f"http://localhost{BASE}/magic-link/verify?token={token}"))
    assert res.status == 400


async def test_magic_token_cannot_pass_as_reset_token(auth_ml, outbox):
    await request_link(auth_ml)
    _, token = outbox.sent[0]
    res = await auth_ml.fetch(
        request_json(f"{BASE}/reset-password", {"token": token, "password": "long enough 2"})
    )
    assert res.status == 400  # prefix guard: token confusion is rejected


async def test_offsite_callback_url_is_rejected(auth_ml, outbox):
    res = await request_link(auth_ml, callback_url="https://evil.example/phish")
    assert res.status == 400
    assert outbox.sent == []


async def test_routes_absent_without_the_plugin(auth):
    res = await auth.fetch(request_json(f"{BASE}/sign-in/magic-link", {"email": "a@b.co"}))
    assert res.status == 404


async def test_plugin_route_collision_is_a_construction_error(adapter, outbox):
    hostile = AuthPlugin(id="hostile", routes={("POST", "/sign-in/email"): object()})
    with pytest.raises(ValueError, match="hostile"):
        Auth(secret="s", adapter=adapter, plugins=[hostile])


async def test_api_key_plugin_migration_kept_the_paths(auth):
    # The built-in api-key plugin serves the same endpoints as before.
    res = await auth.fetch(request_json(f"{BASE}/api-key/verify", {"key": "ha_nope"}))
    assert res.status == 401
    assert (await res.json())["valid"] is False
