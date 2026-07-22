"""Standards-header CSRF checks (Origin + Sec-Fetch-Site), DESIGN §9."""

from conftest import request_json

SIGNOUT = "/api/auth/sign-out"


async def test_same_origin_post_passes(auth):
    res = await auth.fetch(request_json(SIGNOUT, {}, origin="http://localhost"))
    assert res.status == 200


async def test_cross_origin_post_is_403(auth):
    res = await auth.fetch(request_json(SIGNOUT, {}, origin="https://evil.example"))
    assert res.status == 403


async def test_trusted_origin_passes(adapter):
    from hayate_auth import Auth, ScryptBackend

    auth = Auth(
        secret="s",
        adapter=adapter,
        crypto=ScryptBackend(log_n=12),
        trusted_origins=["https://app.example.com"],
    )
    res = await auth.fetch(request_json(SIGNOUT, {}, origin="https://app.example.com"))
    assert res.status == 200


async def test_fetch_metadata_cross_site_is_403(auth):
    res = await auth.fetch(request_json(SIGNOUT, {}, headers={"sec-fetch-site": "cross-site"}))
    assert res.status == 403


async def test_fetch_metadata_same_origin_passes(auth):
    res = await auth.fetch(request_json(SIGNOUT, {}, headers={"sec-fetch-site": "same-origin"}))
    assert res.status == 200


async def test_headerless_client_passes(auth):
    """curl and server-to-server clients send neither header."""
    res = await auth.fetch(request_json(SIGNOUT, {}))
    assert res.status == 200


async def test_get_is_never_blocked(auth):
    res = await auth.fetch(
        request_json(
            "/api/auth/get-session",
            method="GET",
            origin="https://evil.example",
        )
    )
    assert res.status == 200
