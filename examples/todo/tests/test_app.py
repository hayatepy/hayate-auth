"""The acceptance flow: sign up, use the protected API, sign out."""

from app import app


async def _cookie(res) -> str:
    return res.headers.get("set-cookie").split(";", 1)[0]


async def test_anonymous_is_401():
    res = await app.request("/todos")
    assert res.status == 401


async def test_login_and_todo_flow():
    signup = await app.request(
        "/api/auth/sign-up/email",
        method="POST",
        json={"email": "demo@example.com", "password": "long enough"},
    )
    assert signup.status == 200
    cookie = await _cookie(signup)

    created = await app.request(
        "/todos", method="POST", json={"title": "ship auth"}, headers={"cookie": cookie}
    )
    assert created.status == 201

    listed = await app.request("/todos", headers={"cookie": cookie})
    assert [t["title"] for t in await listed.json()] == ["ship auth"]

    out = await app.request("/api/auth/sign-out", method="POST", headers={"cookie": cookie})
    assert out.status == 200
    assert (await app.request("/todos", headers={"cookie": cookie})).status == 401
