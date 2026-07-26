"""D1Adapter against an in-process fake of the D1 prepare/bind/all API,
backed by a real sqlite3 database — the SQL itself is exercised for real."""

import asyncio
import base64
import hashlib
import sqlite3
import time
from urllib.parse import urlencode

import pytest
from hayate import Request

from conftest import cookie_pair, request_json
from hayate_auth import Auth, AuthorizationServer, ScryptBackend, totp
from hayate_auth.adapter import Where
from hayate_auth.adapters.d1 import D1Adapter
from hayate_auth.schema import SQLITE_SCHEMA


class FakeResult:
    def __init__(self, rows, changes):
        self.results = rows
        self.meta = type("Meta", (), {"changes": changes})()


class FakeStatement:
    def __init__(self, conn, sql, params=()):
        self._conn = conn
        self._sql = sql
        self._params = params

    def bind(self, *params):
        return FakeStatement(self._conn, self._sql, params)

    async def all(self):
        cursor = self._conn.execute(self._sql, self._params)
        rows = [dict(r) for r in cursor.fetchall()]
        self._conn.commit()
        return FakeResult(rows, cursor.rowcount)


class FakeD1:
    def __init__(self):
        self._conn = sqlite3.connect(":memory:")
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SQLITE_SCHEMA)

    def prepare(self, sql):
        return FakeStatement(self._conn, sql)


@pytest.fixture
def adapter():
    return D1Adapter(FakeD1())


def _user(i: int) -> dict:
    return {
        "id": f"u{i}",
        "email": f"u{i}@example.com",
        "email_verified": 0,
        "name": None,
        "image": None,
        "created_at": f"2026-07-2{i}T00:00:00+00:00",
        "updated_at": f"2026-07-2{i}T00:00:00+00:00",
    }


async def test_crud_round_trip(adapter):
    await adapter.create("user", _user(1))
    row = await adapter.find_one("user", [Where("id", "u1")])
    assert row["email"] == "u1@example.com"

    updated = await adapter.update("user", [Where("id", "u1")], {"name": "Ada"})
    assert updated["name"] == "Ada"

    assert await adapter.delete("user", [Where("id", "u1")]) == 1
    assert await adapter.find_one("user", [Where("id", "u1")]) is None


async def test_update_many_returns_affected_count_for_guarded_transition(adapter):
    await adapter.create("user", _user(1))
    assert (
        await adapter.update_many(
            "user",
            [Where("id", "u1"), Where("email_verified", 0)],
            {"email_verified": 1},
        )
        == 1
    )
    assert (
        await adapter.update_many(
            "user",
            [Where("id", "u1"), Where("email_verified", 0)],
            {"email_verified": 1},
        )
        == 0
    )


async def test_operators_sort_limit(adapter):
    for i in range(1, 4):
        await adapter.create("user", _user(i))
    newest = await adapter.find_many("user", [], sort=("created_at", "desc"), limit=1)
    assert newest[0]["id"] == "u3"
    chosen = await adapter.find_many("user", [Where("id", ["u1", "u3"], "in")])
    assert {r["id"] for r in chosen} == {"u1", "u3"}
    others = await adapter.find_many("user", [Where("id", "u2", "ne")])
    assert {r["id"] for r in others} == {"u1", "u3"}


async def test_session_activity_compare_and_swap_has_one_d1_winner(adapter):
    await adapter.create("user", _user(1))
    old = "2026-07-27T00:00:00+00:00"
    await adapter.create(
        "session",
        {
            "id": "session-1",
            "token_hash": "hash-1",
            "user_id": "u1",
            "expires_at": "2026-08-03T00:00:00+00:00",
            "ip_address": None,
            "user_agent": "D1 test",
            "last_active_at": old,
            "created_at": old,
        },
    )

    async def touch(stamp):
        return await adapter.update_many(
            "session",
            [Where("id", "session-1"), Where("last_active_at", old)],
            {"last_active_at": stamp},
        )

    results = await asyncio.gather(
        touch("2026-07-27T00:05:00+00:00"),
        touch("2026-07-27T00:05:01+00:00"),
    )
    assert sorted(results) == [0, 1]


async def test_identifier_validation_still_applies(adapter):
    with pytest.raises(ValueError):
        await adapter.create("user", {"evil": 1})


async def test_d1_totp_step_redemption_is_atomic_and_single_use(adapter):
    auth = Auth(secret="test-secret", adapter=adapter, crypto=ScryptBackend(log_n=12))
    signup = await auth.fetch(
        request_json(
            "/api/auth/sign-up/email",
            {"email": "d1-2fa@example.com", "password": "long enough"},
        )
    )
    session_cookie = cookie_pair(signup)
    enrollment = await auth.fetch(
        request_json("/api/auth/two-factor/enable", {}, cookie=session_cookie)
    )
    secret = (await enrollment.json())["secret"]
    code = totp.code_at(secret, time.time())
    verified = await auth.fetch(
        request_json("/api/auth/two-factor/verify", {"code": code}, cookie=session_cookie)
    )
    assert verified.status == 200

    password = await auth.fetch(
        request_json(
            "/api/auth/sign-in/email",
            {"email": "d1-2fa@example.com", "password": "long enough"},
        )
    )
    challenge = cookie_pair(password)
    first = await auth.fetch(
        request_json("/api/auth/sign-in/two-factor", {"code": code}, cookie=challenge)
    )
    replay = await auth.fetch(
        request_json("/api/auth/sign-in/two-factor", {"code": code}, cookie=challenge)
    )
    assert first.status == 200
    assert replay.status == 401


async def test_d1_consent_revocation_wins_against_in_flight_token_mint(adapter, monkeypatch):
    auth = Auth(
        secret="test-secret",
        adapter=adapter,
        crypto=ScryptBackend(log_n=12),
        authorization_server=AuthorizationServer(
            issuer="http://localhost",
            login_url="/login",
            consent_url="/consent",
        ),
    )
    signup = await auth.fetch(
        request_json(
            "/api/auth/sign-up/email",
            {"email": "d1-oauth@example.com", "password": "long enough"},
        )
    )
    user_id = (await signup.json())["user"]["id"]
    session_cookie = cookie_pair(signup)
    registered = await auth.fetch(
        request_json(
            "/api/auth/oauth2/register",
            {
                "redirect_uris": ["https://client.example/cb"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
            },
        )
    )
    client = await registered.json()
    stamp = "2026-07-27T00:00:00+00:00"
    grant_id = "grant-1"
    await adapter.create(
        "oauth_consent",
        {
            "id": "consent-1",
            "user_id": user_id,
            "client_id": client["client_id"],
            "grant_id": grant_id,
            "scope": "mcp",
            "revoked": 0,
            "created_at": stamp,
            "updated_at": stamp,
        },
    )
    code = "authorization-code"
    verifier = "v" * 43
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    await adapter.create(
        "oauth_code",
        {
            "id": "code-1",
            "code_hash": hashlib.sha256(code.encode()).hexdigest(),
            "client_id": client["client_id"],
            "user_id": user_id,
            "grant_id": grant_id,
            "redirect_uri": client["redirect_uris"][0],
            "scope": "mcp",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": None,
            "used": 0,
            "family_id": None,
            "expires_at": "2099-01-01T00:00:00+00:00",
            "created_at": stamp,
        },
    )

    create_started = asyncio.Event()
    resume_create = asyncio.Event()
    original_create = adapter.create

    async def paused_create(model, data):
        if model == "oauth_token":
            create_started.set()
            await resume_create.wait()
        return await original_create(model, data)

    monkeypatch.setattr(adapter, "create", paused_create)
    exchange = asyncio.create_task(
        auth.fetch(
            Request(
                "http://localhost/api/auth/oauth2/token",
                method="POST",
                headers={"content-type": "application/x-www-form-urlencoded"},
                body=urlencode(
                    {
                        "grant_type": "authorization_code",
                        "code": code,
                        "code_verifier": verifier,
                        "redirect_uri": client["redirect_uris"][0],
                        "client_id": client["client_id"],
                    }
                ),
            )
        )
    )
    await create_started.wait()
    revoked = await auth.fetch(
        request_json(
            "/api/auth/oauth2/consents/revoke",
            {"client_id": client["client_id"]},
            cookie=session_cookie,
        )
    )
    assert revoked.status == 200
    resume_create.set()
    response = await exchange
    assert response.status == 400
    rows = await adapter.find_many("oauth_token", [])
    assert len(rows) == 1
    assert rows[0]["revoked"] != 0
