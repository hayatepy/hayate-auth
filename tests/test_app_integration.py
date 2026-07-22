"""auth.register(app) + require_session through a real Hayate app.

This is the better-auth mounting recipe end to end: two catch-all routes,
middleware-guarded handlers, all exercised via app.request (no server).
"""

from hayate import Context, Hayate

from conftest import cookie_pair


def build_app(auth):
    app = Hayate()
    auth.register(app)

    @app.get("/me", auth.require_session())
    async def me(c: Context):
        return c.json({"me": c.get("user")["email"], "session_id": c.get("session")["id"]})

    return app


async def test_full_flow_through_the_app(auth):
    app = build_app(auth)

    res = await app.request(
        "/api/auth/sign-up/email",
        method="POST",
        json={"email": "app@example.com", "password": "long enough"},
    )
    assert res.status == 200
    cookie = cookie_pair(res)

    session = await app.request("/api/auth/get-session", headers={"cookie": cookie})
    assert (await session.json())["user"]["email"] == "app@example.com"

    me = await app.request("/me", headers={"cookie": cookie})
    assert me.status == 200
    assert (await me.json())["me"] == "app@example.com"


async def test_require_session_rejects_anonymous_with_problem_details(auth):
    app = build_app(auth)
    res = await app.request("/me")
    assert res.status == 401
    assert res.headers.get("content-type").startswith("application/problem+json")


async def test_mounted_auth_still_404s_unknown_subpaths(auth):
    app = build_app(auth)
    res = await app.request("/api/auth/definitely-not-a-route")
    assert res.status == 404
