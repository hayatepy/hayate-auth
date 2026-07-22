"""Sign-up / sign-in / get-session / sign-out through the pure fetch core."""

from conftest import cookie_pair, request_json

SIGNUP = "/api/auth/sign-up/email"
SIGNIN = "/api/auth/sign-in/email"
SESSION = "/api/auth/get-session"
SIGNOUT = "/api/auth/sign-out"


async def test_sign_up_returns_user_and_session_cookie(auth):
    res = await auth.fetch(
        request_json(SIGNUP, {"email": "  Ada@Example.COM ", "password": "correct horse"})
    )
    assert res.status == 200
    user = (await res.json())["user"]
    assert user["email"] == "ada@example.com"
    assert user["email_verified"] is False
    assert "password" not in user and "password_hash" not in user

    cookie = res.headers.get("set-cookie")
    assert cookie.startswith("hayate_auth.session=")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie and "Path=/" in cookie


async def test_https_uses_host_prefix_and_secure(auth):
    res = await auth.fetch(
        request_json(SIGNUP, {"email": "a@example.com", "password": "long enough"}, scheme="https")
    )
    cookie = res.headers.get("set-cookie")
    assert cookie.startswith("__Host-hayate_auth.session=")
    assert "Secure" in cookie


async def test_duplicate_email_is_422(auth):
    body = {"email": "dup@example.com", "password": "long enough"}
    assert (await auth.fetch(request_json(SIGNUP, body))).status == 200
    assert (await auth.fetch(request_json(SIGNUP, body))).status == 422


async def test_validation_errors_are_400(auth):
    cases = [
        {"email": "not-an-email", "password": "long enough"},
        {"email": "a@example.com", "password": "short"},
        {"email": "a@example.com"},
        {"password": "long enough"},
    ]
    for body in cases:
        assert (await auth.fetch(request_json(SIGNUP, body))).status == 400, body
    assert (await auth.fetch(request_json(SIGNUP, None))).status == 400


async def test_sign_in_round_trip(auth):
    await auth.fetch(request_json(SIGNUP, {"email": "kay@example.com", "password": "long enough"}))
    res = await auth.fetch(
        request_json(SIGNIN, {"email": "kay@example.com", "password": "long enough"})
    )
    assert res.status == 200

    session_res = await auth.fetch(request_json(SESSION, method="GET", cookie=cookie_pair(res)))
    data = await session_res.json()
    assert data["user"]["email"] == "kay@example.com"
    assert data["session"]["user_id"] == data["user"]["id"]
    assert "token_hash" not in data["session"]


async def test_wrong_password_and_unknown_user_are_identical_401s(auth):
    await auth.fetch(request_json(SIGNUP, {"email": "eve@example.com", "password": "long enough"}))
    wrong = await auth.fetch(
        request_json(SIGNIN, {"email": "eve@example.com", "password": "wrong password"})
    )
    unknown = await auth.fetch(
        request_json(SIGNIN, {"email": "ghost@example.com", "password": "wrong password"})
    )
    assert wrong.status == unknown.status == 401
    assert await wrong.text() == await unknown.text()


async def test_get_session_without_cookie_is_null(auth):
    res = await auth.fetch(request_json(SESSION, method="GET"))
    assert res.status == 200
    assert await res.json() == {"session": None, "user": None}


async def test_sign_out_revokes_and_clears(auth):
    signup = await auth.fetch(
        request_json(SIGNUP, {"email": "bye@example.com", "password": "long enough"})
    )
    cookie = cookie_pair(signup)

    out = await auth.fetch(request_json(SIGNOUT, {}, cookie=cookie))
    assert out.status == 200
    assert "Max-Age=0" in out.headers.get("set-cookie")

    after = await auth.fetch(request_json(SESSION, method="GET", cookie=cookie))
    assert await after.json() == {"session": None, "user": None}


async def test_unknown_paths_are_404(auth):
    assert (await auth.fetch(request_json("/api/auth/nope", {}))).status == 404
    assert (await auth.fetch(request_json("/elsewhere", {}))).status == 404
