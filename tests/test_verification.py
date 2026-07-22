"""Email verification and password reset (v0.2)."""

from datetime import UTC, datetime, timedelta

import pytest

from conftest import cookie_pair, request_json
from hayate_auth import Auth, ScryptBackend

SIGNUP = "/api/auth/sign-up/email"
SIGNIN = "/api/auth/sign-in/email"
FORGET = "/api/auth/forget-password"
RESET = "/api/auth/reset-password"


class Outbox:
    def __init__(self):
        self.reset: list[tuple[dict, str]] = []
        self.verify: list[tuple[dict, str]] = []

    async def send_reset(self, user, token):
        self.reset.append((user, token))

    async def send_verify(self, user, token):
        self.verify.append((user, token))


@pytest.fixture
def outbox():
    return Outbox()


@pytest.fixture
def auth(adapter, outbox):
    return Auth(
        secret="s",
        adapter=adapter,
        crypto=ScryptBackend(log_n=12),
        send_reset_password=outbox.send_reset,
        send_verification_email=outbox.send_verify,
    )


async def test_full_reset_flow(auth, outbox, adapter):
    await auth.fetch(request_json(SIGNUP, {"email": "r@example.com", "password": "old password"}))
    res = await auth.fetch(request_json(FORGET, {"email": "r@example.com"}))
    assert res.status == 200
    ((user, token),) = outbox.reset
    assert user["email"] == "r@example.com"

    res = await auth.fetch(request_json(RESET, {"token": token, "password": "new password!"}))
    assert res.status == 200

    old = await auth.fetch(
        request_json(SIGNIN, {"email": "r@example.com", "password": "old password"})
    )
    new = await auth.fetch(
        request_json(SIGNIN, {"email": "r@example.com", "password": "new password!"})
    )
    assert old.status == 401
    assert new.status == 200


async def test_reset_revokes_every_session(auth, outbox, adapter):
    signup = await auth.fetch(
        request_json(SIGNUP, {"email": "s@example.com", "password": "old password"})
    )
    cookie = cookie_pair(signup)
    await auth.fetch(request_json(FORGET, {"email": "s@example.com"}))
    ((_, token),) = outbox.reset
    await auth.fetch(request_json(RESET, {"token": token, "password": "new password!"}))

    session = await auth.fetch(request_json("/api/auth/get-session", method="GET", cookie=cookie))
    assert await session.json() == {"session": None, "user": None}


async def test_forget_never_reveals_existence(auth, outbox):
    known = await auth.fetch(request_json(FORGET, {"email": "ghost@example.com"}))
    assert known.status == 200
    assert await known.json() == {"success": True}
    assert outbox.reset == []


async def test_reset_token_is_single_use(auth, outbox):
    await auth.fetch(request_json(SIGNUP, {"email": "o@example.com", "password": "old password"}))
    await auth.fetch(request_json(FORGET, {"email": "o@example.com"}))
    ((_, token),) = outbox.reset
    first = await auth.fetch(request_json(RESET, {"token": token, "password": "new password!"}))
    second = await auth.fetch(request_json(RESET, {"token": token, "password": "third one!!"}))
    assert first.status == 200
    assert second.status == 400


async def test_expired_reset_token_rejected(auth, outbox, adapter):
    await auth.fetch(request_json(SIGNUP, {"email": "e@example.com", "password": "old password"}))
    await auth.fetch(request_json(FORGET, {"email": "e@example.com"}))
    ((_, token),) = outbox.reset
    past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat(timespec="seconds")
    await adapter.update("verification", [], {"expires_at": past})
    res = await auth.fetch(request_json(RESET, {"token": token, "password": "new password!"}))
    assert res.status == 400


async def test_email_verification_flow(auth, outbox, adapter):
    signup = await auth.fetch(
        request_json(SIGNUP, {"email": "v@example.com", "password": "long enough"})
    )
    assert (await signup.json())["user"]["email_verified"] is False
    ((user, token),) = outbox.verify

    res = await auth.fetch(request_json(f"/api/auth/verify-email?token={token}", method="GET"))
    assert res.status == 200

    from hayate_auth.adapter import Where

    row = await adapter.find_one("user", [Where("id", user["id"])])
    assert row["email_verified"] == 1


async def test_verify_token_cannot_reset_password(auth, outbox):
    """Token confusion: a verify token must not pass the reset endpoint."""
    await auth.fetch(request_json(SIGNUP, {"email": "x@example.com", "password": "long enough"}))
    ((_, verify_token),) = outbox.verify
    res = await auth.fetch(
        request_json(RESET, {"token": verify_token, "password": "new password!"})
    )
    assert res.status == 400


async def test_unconfigured_reset_is_501(adapter):
    bare = Auth(secret="s", adapter=adapter, crypto=ScryptBackend(log_n=12))
    res = await bare.fetch(request_json(FORGET, {"email": "a@example.com"}))
    assert res.status == 501
