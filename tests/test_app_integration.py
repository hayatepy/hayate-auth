"""auth.register(app) + require_session through a real Hayate app.

This is the better-auth mounting recipe end to end: two catch-all routes,
middleware-guarded handlers, all exercised via app.request (no server).
"""

from hayate import Context, Hayate

from conftest import cookie_pair, request_json
from hayate_auth import LazyAuth


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


async def test_api_key_bearer_middleware_exposes_principal_and_enforces_scope(auth):
    cookie = cookie_pair(
        await auth.fetch(
            request_json(
                "/api/auth/sign-up/email",
                {"email": "bearer@example.com", "password": "long enough"},
            )
        )
    )
    created = await auth.fetch(
        request_json(
            "/api/auth/api-key/create",
            {"scopes": ["documents:read"]},
            cookie=cookie,
        )
    )
    key = (await created.json())["key"]
    app = Hayate()

    @app.get("/documents", auth.require_api_key("documents:read"))
    async def documents(c: Context):
        principal = c.get("principal")
        return c.json(
            {
                "subject": principal["subject"],
                "credential_type": principal["credential_type"],
            }
        )

    ok = await app.request("/documents", headers={"authorization": f"Bearer {key}"})
    assert ok.status == 200
    assert (await ok.json())["credential_type"] == "api_key"

    missing = await app.request("/documents")
    assert missing.status == 401
    assert missing.headers.get("www-authenticate") == "Bearer"
    malformed = await app.request(
        "/documents",
        headers={"authorization": f"Bearer {key} extra"},
    )
    assert malformed.status == 401

    insufficient_app = Hayate()

    @insufficient_app.get("/admin", auth.require_api_key("admin"))
    async def admin(c: Context):
        return c.text("ok")

    denied = await insufficient_app.request("/admin", headers={"authorization": f"Bearer {key}"})
    assert denied.status == 403
    assert 'error="insufficient_scope"' in denied.headers.get("www-authenticate")
    assert 'scope="admin"' in denied.headers.get("www-authenticate")


async def test_lazy_auth_registers_once_after_request_context_exists(auth):
    calls = 0

    def factory(c: Context):
        nonlocal calls
        calls += 1
        assert c.env == {"binding": "available"}
        return auth

    app = Hayate(env={"binding": "available"})
    LazyAuth(factory).register(app)

    first = await app.request("/api/auth/get-session")
    second = await app.request("/api/auth/get-session")
    assert first.status == 200
    assert second.status == 200
    assert calls == 1


def test_require_middleware_and_security_schemes_share_names(auth):
    session_middleware = auth.require_session()
    api_key_middleware = auth.require_api_key("documents:read")
    schemes = auth.openapi_security_schemes()

    assert session_middleware.__openapi_security__ == [{"SessionCookie": []}]
    assert api_key_middleware.__openapi_security__ == [{"ApiKeyBearer": ["documents:read"]}]
    assert schemes["SessionCookie"]["in"] == "cookie"
    assert schemes["ApiKeyBearer"]["scheme"] == "bearer"
