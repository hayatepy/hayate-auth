"""TOTP two-factor: primitives, enrollment, and two-step sign-in."""

import time

from conftest import cookie_pair, request_json
from hayate_auth import totp

SIGNUP = "/api/auth/sign-up/email"
SIGNIN = "/api/auth/sign-in/email"
SESSION = "/api/auth/get-session"
ENABLE = "/api/auth/two-factor/enable"
VERIFY = "/api/auth/two-factor/verify"
DISABLE = "/api/auth/two-factor/disable"
TWO_FACTOR_SIGNIN = "/api/auth/sign-in/two-factor"


# -- primitives (RFC 6238) ----------------------------------------------------


def test_rfc6238_test_vector():
    # RFC 6238 Appendix B: SHA-1, seed "12345678901234567890" (ASCII) in Base32,
    # T=59s -> 94287082 (last 8); with DIGITS=6 the low 6 are "287082".
    import base64

    secret = base64.b32encode(b"12345678901234567890").decode()
    assert totp.code_at(secret, 59) == "287082"


def test_verify_accepts_current_and_adjacent_windows():
    secret = totp.generate_secret()
    now = 1_000_000_000
    assert totp.verify(secret, totp.code_at(secret, now), at=now)
    assert totp.verify(secret, totp.code_at(secret, now - 30), at=now)
    assert totp.verify(secret, totp.code_at(secret, now + 30), at=now)
    assert not totp.verify(secret, totp.code_at(secret, now + 120), at=now)


def test_verify_rejects_garbage():
    secret = totp.generate_secret()
    assert not totp.verify(secret, "")
    assert not totp.verify(secret, "abcdef")


def test_provisioning_uri():
    uri = totp.provisioning_uri("ABC", account_name="a@b.com", issuer="MyApp")
    assert uri.startswith("otpauth://totp/MyApp:a%40b.com?")
    assert "secret=ABC" in uri and "issuer=MyApp" in uri


# -- enrollment + sign-in -----------------------------------------------------


async def _signup(auth, email="t@example.com") -> str:
    res = await auth.fetch(request_json(SIGNUP, {"email": email, "password": "long enough"}))
    return cookie_pair(res)


async def _enroll(auth, cookie) -> str:
    res = await auth.fetch(request_json(ENABLE, {}, cookie=cookie))
    secret = (await res.json())["secret"]
    code = totp.code_at(secret, time.time())
    confirmed = await auth.fetch(request_json(VERIFY, {"code": code}, cookie=cookie))
    assert confirmed.status == 200
    return secret


async def test_enable_returns_secret_and_uri(auth):
    cookie = await _signup(auth)
    res = await auth.fetch(request_json(ENABLE, {}, cookie=cookie))
    assert res.status == 200
    body = await res.json()
    assert body["secret"] and body["uri"].startswith("otpauth://totp/")


async def test_enable_requires_authentication(auth):
    res = await auth.fetch(request_json(ENABLE, {}))
    assert res.status == 401


async def test_verify_bad_code_does_not_enable(auth, adapter):
    cookie = await _signup(auth)
    await auth.fetch(request_json(ENABLE, {}, cookie=cookie))
    res = await auth.fetch(request_json(VERIFY, {"code": "000000"}, cookie=cookie))
    assert res.status == 400
    row = await adapter.find_one("two_factor", [])
    assert row["enabled"] == 0


async def test_sign_in_becomes_two_step_when_enabled(auth):
    cookie = await _signup(auth, "2fa@example.com")
    secret = await _enroll(auth, cookie)

    first = await auth.fetch(
        request_json(SIGNIN, {"email": "2fa@example.com", "password": "long enough"})
    )
    assert first.status == 200
    body = await first.json()
    assert body == {"two_factor_required": True}
    assert "user" not in body
    challenge = cookie_pair(first)

    code = totp.code_at(secret, time.time())
    second = await auth.fetch(request_json(TWO_FACTOR_SIGNIN, {"code": code}, cookie=challenge))
    assert second.status == 200
    session_cookie = cookie_pair(second)
    who = await auth.fetch(request_json(SESSION, method="GET", cookie=session_cookie))
    assert (await who.json())["user"]["email"] == "2fa@example.com"


async def test_two_factor_sign_in_rejects_wrong_code(auth):
    cookie = await _signup(auth, "w@example.com")
    await _enroll(auth, cookie)
    first = await auth.fetch(
        request_json(SIGNIN, {"email": "w@example.com", "password": "long enough"})
    )
    challenge = cookie_pair(first)
    res = await auth.fetch(request_json(TWO_FACTOR_SIGNIN, {"code": "000000"}, cookie=challenge))
    assert res.status == 401


async def test_two_factor_sign_in_needs_the_challenge_cookie(auth):
    cookie = await _signup(auth, "n@example.com")
    secret = await _enroll(auth, cookie)
    code = totp.code_at(secret, time.time())
    res = await auth.fetch(request_json(TWO_FACTOR_SIGNIN, {"code": code}))
    assert res.status == 400


async def test_password_alone_never_yields_a_session_with_2fa(auth):
    cookie = await _signup(auth, "strict@example.com")
    await _enroll(auth, cookie)
    first = await auth.fetch(
        request_json(SIGNIN, {"email": "strict@example.com", "password": "long enough"})
    )
    # The challenge cookie is not a session cookie.
    challenge = cookie_pair(first)
    who = await auth.fetch(request_json(SESSION, method="GET", cookie=challenge))
    assert await who.json() == {"session": None, "user": None}


async def test_disable_turns_sign_in_back_to_one_step(auth):
    cookie = await _signup(auth, "off@example.com")
    secret = await _enroll(auth, cookie)
    code = totp.code_at(secret, time.time())
    disabled = await auth.fetch(request_json(DISABLE, {"code": code}, cookie=cookie))
    assert disabled.status == 200

    res = await auth.fetch(
        request_json(SIGNIN, {"email": "off@example.com", "password": "long enough"})
    )
    assert res.status == 200
    assert "user" in await res.json()


async def test_wrong_password_still_generic_401_with_2fa(auth):
    cookie = await _signup(auth, "wp@example.com")
    await _enroll(auth, cookie)
    res = await auth.fetch(
        request_json(SIGNIN, {"email": "wp@example.com", "password": "wrong password"})
    )
    assert res.status == 401
    # Must not reveal that 2FA is set up.
    assert "two_factor_required" not in await res.json()
