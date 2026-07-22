"""Attack regressions (DESIGN §13): fixation, replay, expiry, enumeration."""

from datetime import UTC, datetime, timedelta

from conftest import cookie_pair, request_json
from hayate_auth.adapter import Where

SIGNUP = "/api/auth/sign-up/email"
SIGNIN = "/api/auth/sign-in/email"
SESSION = "/api/auth/get-session"
SIGNOUT = "/api/auth/sign-out"


async def test_sign_in_rotates_the_session_token(auth):
    """Session fixation: a pre-login cookie must never stay valid post-login."""
    signup = await auth.fetch(
        request_json(SIGNUP, {"email": "fix@example.com", "password": "long enough"})
    )
    signin = await auth.fetch(
        request_json(SIGNIN, {"email": "fix@example.com", "password": "long enough"})
    )
    assert cookie_pair(signup) != cookie_pair(signin)


async def test_revoked_token_cannot_be_replayed(auth):
    signup = await auth.fetch(
        request_json(SIGNUP, {"email": "replay@example.com", "password": "long enough"})
    )
    cookie = cookie_pair(signup)
    await auth.fetch(request_json(SIGNOUT, {}, cookie=cookie))

    replayed = await auth.fetch(request_json(SESSION, method="GET", cookie=cookie))
    assert await replayed.json() == {"session": None, "user": None}


async def test_expired_session_is_rejected_and_deleted(auth, adapter):
    signup = await auth.fetch(
        request_json(SIGNUP, {"email": "old@example.com", "password": "long enough"})
    )
    cookie = cookie_pair(signup)
    past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat(timespec="seconds")
    await adapter.update("session", [], {"expires_at": past})

    res = await auth.fetch(request_json(SESSION, method="GET", cookie=cookie))
    assert await res.json() == {"session": None, "user": None}
    assert await adapter.find_many("session", []) == []


async def test_unknown_user_still_burns_a_kdf(auth):
    """Enumeration timing: the dummy verification must actually run."""
    calls: list[str] = []
    inner = auth.crypto

    class Spy:
        async def hash_password(self, password):
            return await inner.hash_password(password)

        async def verify_password(self, password, stored):
            calls.append(stored)
            return await inner.verify_password(password, stored)

    auth.crypto = Spy()
    res = await auth.fetch(
        request_json(SIGNIN, {"email": "ghost@example.com", "password": "whatever!"})
    )
    assert res.status == 401
    assert len(calls) == 1  # the dummy hash was verified


async def test_forged_token_is_rejected(auth):
    signup = await auth.fetch(
        request_json(SIGNUP, {"email": "forge@example.com", "password": "long enough"})
    )
    cookie = cookie_pair(signup)
    forged = cookie[:-4] + ("AAAA" if not cookie.endswith("AAAA") else "BBBB")
    res = await auth.fetch(request_json(SESSION, method="GET", cookie=forged))
    assert await res.json() == {"session": None, "user": None}


async def test_database_never_stores_the_raw_token(auth, adapter):
    signup = await auth.fetch(
        request_json(SIGNUP, {"email": "hash@example.com", "password": "long enough"})
    )
    raw_token = cookie_pair(signup).split("=", 1)[1]
    rows = await adapter.find_many("session", [])
    assert len(rows) == 1
    assert rows[0]["token_hash"] != raw_token
    assert raw_token not in str(rows[0])


async def test_password_hash_is_phc_not_plaintext(auth, adapter):
    await auth.fetch(request_json(SIGNUP, {"email": "phc@example.com", "password": "long enough"}))
    account = await adapter.find_one("account", [Where("provider_id", "credential")])
    assert account["password_hash"].startswith("$scrypt$")
    assert "long enough" not in account["password_hash"]
