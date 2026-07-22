"""API keys: create/verify/list/delete + Auth.verify_api_key (mcp integration)."""

from datetime import UTC, datetime, timedelta

from conftest import cookie_pair, request_json

SIGNUP = "/api/auth/sign-up/email"
CREATE = "/api/auth/api-key/create"
VERIFY = "/api/auth/api-key/verify"
LIST = "/api/auth/api-key/list"
DELETE = "/api/auth/api-key/delete"


async def _signup(auth, email="k@example.com") -> str:
    res = await auth.fetch(request_json(SIGNUP, {"email": email, "password": "long enough"}))
    return cookie_pair(res)


async def test_create_returns_key_once_and_stores_only_the_hash(auth, adapter):
    cookie = await _signup(auth)
    res = await auth.fetch(request_json(CREATE, {"name": "ci", "scopes": ["read"]}, cookie=cookie))
    assert res.status == 201
    body = await res.json()
    key = body["key"]
    assert key.startswith("ha_")
    assert body["name"] == "ci" and body["scopes"] == ["read"]
    assert body["prefix"] == key[:11]

    row = await adapter.find_one("api_key", [])
    assert "key" not in row  # only the hash column exists
    assert row["key_hash"] != key and key not in str(row)


async def test_verify_valid_key_returns_identity(auth):
    cookie = await _signup(auth, "id@example.com")
    created = await auth.fetch(request_json(CREATE, {"scopes": ["a", "b"]}, cookie=cookie))
    key = (await created.json())["key"]

    res = await auth.fetch(request_json(VERIFY, {"key": key}))
    assert res.status == 200
    data = await res.json()
    assert data["valid"] is True
    assert data["scopes"] == ["a", "b"]
    assert data["user_id"]


async def test_verify_rejects_unknown_and_malformed(auth):
    assert (await auth.fetch(request_json(VERIFY, {"key": "ha_nope"}))).status == 401
    assert (await auth.fetch(request_json(VERIFY, {"key": "not-a-key"}))).status == 401
    assert (await auth.fetch(request_json(VERIFY, {"key": ""}))).status == 401


async def test_auth_verify_api_key_method(auth):
    cookie = await _signup(auth, "m@example.com")
    created = await auth.fetch(request_json(CREATE, {}, cookie=cookie))
    key = (await created.json())["key"]

    claims = await auth.verify_api_key(key)
    assert claims is not None and claims["scopes"] == []
    assert await auth.verify_api_key("ha_wrong") is None


async def test_verify_updates_last_used(auth, adapter):
    cookie = await _signup(auth, "u@example.com")
    created = await auth.fetch(request_json(CREATE, {}, cookie=cookie))
    key = (await created.json())["key"]
    assert (await adapter.find_one("api_key", []))["last_used_at"] is None
    await auth.verify_api_key(key)
    assert (await adapter.find_one("api_key", []))["last_used_at"] is not None


async def test_expired_key_is_rejected_and_purged(auth, adapter):
    cookie = await _signup(auth, "e@example.com")
    created = await auth.fetch(request_json(CREATE, {"expires_in": 3600}, cookie=cookie))
    key = (await created.json())["key"]
    past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat(timespec="seconds")
    await adapter.update("api_key", [], {"expires_at": past})

    assert await auth.verify_api_key(key) is None
    assert await adapter.find_many("api_key", []) == []


async def test_list_and_delete(auth):
    cookie = await _signup(auth, "l@example.com")
    a = await (await auth.fetch(request_json(CREATE, {"name": "one"}, cookie=cookie))).json()
    await auth.fetch(request_json(CREATE, {"name": "two"}, cookie=cookie))

    listed = await auth.fetch(request_json(LIST, method="GET", cookie=cookie))
    keys = (await listed.json())["keys"]
    assert {k["name"] for k in keys} == {"one", "two"}
    assert all("key" not in k and "key_hash" not in k for k in keys)

    deleted = await auth.fetch(request_json(DELETE, {"id": a["id"]}, cookie=cookie))
    assert deleted.status == 200
    remaining = await (await auth.fetch(request_json(LIST, method="GET", cookie=cookie))).json()
    assert [k["name"] for k in remaining["keys"]] == ["two"]


async def test_create_requires_authentication(auth):
    assert (await auth.fetch(request_json(CREATE, {}))).status == 401


async def test_cannot_delete_another_users_key(auth):
    owner = await _signup(auth, "owner@example.com")
    created = await auth.fetch(request_json(CREATE, {}, cookie=owner))
    key_id = (await created.json())["id"]

    intruder = await _signup(auth, "intruder@example.com")
    res = await auth.fetch(request_json(DELETE, {"id": key_id}, cookie=intruder))
    assert res.status == 404


async def test_bad_scopes_and_expiry_are_400(auth):
    cookie = await _signup(auth, "v@example.com")
    assert (await auth.fetch(request_json(CREATE, {"scopes": "read"}, cookie=cookie))).status == 400
    assert (await auth.fetch(request_json(CREATE, {"expires_in": -5}, cookie=cookie))).status == 400
