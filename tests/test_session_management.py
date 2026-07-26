import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from conftest import cookie_pair, request_json
from hayate_auth import Auth, ScryptBackend
from hayate_auth import session as sessions
from hayate_auth.adapter import Where

SIGNUP = "/api/auth/sign-up/email"
SIGNIN = "/api/auth/sign-in/email"
GET_SESSION = "/api/auth/get-session"
LIST = "/api/auth/list-sessions"
REVOKE = "/api/auth/revoke-session"
REVOKE_OTHERS = "/api/auth/revoke-other-sessions"
REVOKE_ALL = "/api/auth/revoke-sessions"


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 27, tzinfo=UTC)

    def now(self) -> datetime:
        return self.value

    def advance(self, **kwargs: float) -> None:
        self.value += timedelta(**kwargs)


def make_auth(
    adapter,
    *,
    idle: timedelta | None = timedelta(hours=1),
    touch: timedelta = timedelta(minutes=5),
    fresh: timedelta | None = timedelta(minutes=30),
    ttl: timedelta = timedelta(days=7),
) -> Auth:
    return Auth(
        secret="session-management-test",
        adapter=adapter,
        crypto=ScryptBackend(log_n=12),
        session_ttl=ttl,
        session_idle_timeout=idle,
        session_touch_interval=touch,
        session_fresh_ttl=fresh,
    )


async def sign_up(auth: Auth, email: str, *, user_agent: str = "first browser"):
    return await auth.fetch(
        request_json(
            SIGNUP,
            {"email": email, "password": "unique session password"},
            headers={"user-agent": user_agent},
        )
    )


async def sign_in(auth: Auth, email: str, *, user_agent: str = "second browser"):
    return await auth.fetch(
        request_json(
            SIGNIN,
            {"email": email, "password": "unique session password"},
            headers={"user-agent": user_agent},
        )
    )


async def test_idle_timeout_uses_bounded_activity_touches(adapter, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(sessions, "now", clock.now)
    auth = make_auth(adapter)
    signup = await sign_up(auth, "idle@example.com")
    cookie = cookie_pair(signup)
    original = (await adapter.find_one("session", []))["last_active_at"]

    clock.advance(minutes=4)
    still_fresh = await auth.fetch(request_json(GET_SESSION, method="GET", cookie=cookie))
    assert (await still_fresh.json())["session"] is not None
    assert (await adapter.find_one("session", []))["last_active_at"] == original

    clock.advance(minutes=2)
    touched = await auth.fetch(request_json(GET_SESSION, method="GET", cookie=cookie))
    touched_at = (await touched.json())["session"]["last_active_at"]
    assert touched_at == sessions.isoformat(clock.now())

    clock.advance(hours=1, seconds=1)
    expired = await auth.fetch(request_json(GET_SESSION, method="GET", cookie=cookie))
    assert await expired.json() == {"session": None, "user": None}
    assert await adapter.find_many("session", []) == []


async def test_absolute_expiry_does_not_slide_with_activity(adapter, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(sessions, "now", clock.now)
    auth = make_auth(
        adapter,
        idle=timedelta(minutes=20),
        touch=timedelta(minutes=5),
        ttl=timedelta(minutes=30),
    )
    signup = await sign_up(auth, "absolute@example.com")
    cookie = cookie_pair(signup)

    for _ in range(4):
        clock.advance(minutes=6)
        active = await auth.fetch(request_json(GET_SESSION, method="GET", cookie=cookie))
        assert (await active.json())["session"] is not None

    clock.advance(minutes=7)
    expired = await auth.fetch(request_json(GET_SESSION, method="GET", cookie=cookie))
    assert await expired.json() == {"session": None, "user": None}


class RacingAdapter:
    def __init__(self, inner) -> None:
        self.inner = inner
        self.race = False
        self.initial_reads = 0
        self.both_read = asyncio.Event()
        self.cas_results: list[int] = []

    async def create(self, model, data):
        return await self.inner.create(model, data)

    async def find_one(self, model, where):
        row = await self.inner.find_one(model, where)
        if self.race and model == "session" and self.initial_reads < 2:
            self.initial_reads += 1
            if self.initial_reads == 2:
                self.both_read.set()
            await self.both_read.wait()
        return row

    async def find_many(self, model, where, *, limit=None, sort=None):
        return await self.inner.find_many(model, where, limit=limit, sort=sort)

    async def update(self, model, where, data):
        return await self.inner.update(model, where, data)

    async def update_many(self, model, where, data):
        result = await self.inner.update_many(model, where, data)
        if self.race and model == "session":
            self.cas_results.append(result)
        return result

    async def delete(self, model, where):
        return await self.inner.delete(model, where)


async def test_concurrent_activity_touch_has_exactly_one_write(adapter, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(sessions, "now", clock.now)
    racing = RacingAdapter(adapter)
    auth = make_auth(racing)
    signup = await sign_up(auth, "race@example.com")
    cookie = cookie_pair(signup)
    clock.advance(minutes=6)
    racing.race = True
    request = request_json(GET_SESSION, method="GET", cookie=cookie)

    first, second = await asyncio.gather(
        auth.get_session(request),
        auth.get_session(request),
    )

    assert first is not None
    assert second is not None
    assert sorted(racing.cas_results) == [0, 1]
    row = await adapter.find_one("session", [])
    assert row["last_active_at"] == sessions.isoformat(clock.now())


class PausedTouchAdapter(RacingAdapter):
    def __init__(self, inner) -> None:
        super().__init__(inner)
        self.touch_started = asyncio.Event()
        self.resume_touch = asyncio.Event()

    async def update_many(self, model, where, data):
        if model == "session":
            self.touch_started.set()
            await self.resume_touch.wait()
        return await self.inner.update_many(model, where, data)


async def test_concurrent_revocation_wins_against_activity_touch(adapter, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(sessions, "now", clock.now)
    paused = PausedTouchAdapter(adapter)
    auth = make_auth(paused)
    signup = await sign_up(auth, "revocation-race@example.com")
    cookie = cookie_pair(signup)
    row = await adapter.find_one("session", [])
    clock.advance(minutes=6)

    resolving = asyncio.create_task(
        auth.get_session(request_json(GET_SESSION, method="GET", cookie=cookie))
    )
    await paused.touch_started.wait()
    assert await adapter.delete("session", [Where("id", row["id"])]) == 1
    paused.resume_touch.set()

    assert await resolving is None
    assert await adapter.find_many("session", []) == []


async def test_list_and_revoke_sessions_without_token_material(adapter, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(sessions, "now", clock.now)
    auth = make_auth(adapter)
    first = await sign_up(auth, "manage@example.com")
    first_cookie = cookie_pair(first)
    second = await sign_in(auth, "manage@example.com")
    second_cookie = cookie_pair(second)

    listed = await auth.fetch(request_json(LIST, method="GET", cookie=first_cookie))
    records = await listed.json()
    assert listed.status == 200
    assert len(records) == 2
    assert sum(record["current"] for record in records) == 1
    assert {record["user_agent"] for record in records} == {
        "first browser",
        "second browser",
    }
    assert all("token_hash" not in record and "token" not in record for record in records)

    other_id = next(record["id"] for record in records if not record["current"])
    revoked = await auth.fetch(request_json(REVOKE, {"sessionId": other_id}, cookie=first_cookie))
    assert revoked.status == 200
    second_after = await auth.fetch(request_json(GET_SESSION, method="GET", cookie=second_cookie))
    assert (await second_after.json())["session"] is None

    third_cookie = cookie_pair(await sign_in(auth, "manage@example.com"))
    revoked_others = await auth.fetch(request_json(REVOKE_OTHERS, {}, cookie=first_cookie))
    assert revoked_others.status == 200
    assert (
        await (
            await auth.fetch(request_json(GET_SESSION, method="GET", cookie=third_cookie))
        ).json()
    )["session"] is None
    assert (
        await (
            await auth.fetch(request_json(GET_SESSION, method="GET", cookie=first_cookie))
        ).json()
    )["session"] is not None

    fourth_cookie = cookie_pair(await sign_in(auth, "manage@example.com"))
    revoked_all = await auth.fetch(request_json(REVOKE_ALL, {}, cookie=first_cookie))
    assert revoked_all.status == 200
    assert "Max-Age=0" in revoked_all.headers.get("set-cookie")
    for cookie in (first_cookie, fourth_cookie):
        response = await auth.fetch(request_json(GET_SESSION, method="GET", cookie=cookie))
        assert (await response.json())["session"] is None


async def test_session_list_filters_expired_and_idle_entries(adapter, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(sessions, "now", clock.now)
    auth = make_auth(adapter)
    current = await sign_up(auth, "filtered-list@example.com")
    current_cookie = cookie_pair(current)
    await sign_in(auth, "filtered-list@example.com", user_agent="expired browser")
    await sign_in(auth, "filtered-list@example.com", user_agent="idle browser")
    expired = await adapter.find_one(
        "session",
        [Where("user_agent", "expired browser")],
    )
    idle = await adapter.find_one(
        "session",
        [Where("user_agent", "idle browser")],
    )
    await adapter.update(
        "session",
        [Where("id", expired["id"])],
        {"expires_at": "2026-07-26T00:00:00+00:00"},
    )
    await adapter.update(
        "session",
        [Where("id", idle["id"])],
        {"last_active_at": "2026-07-26T22:00:00+00:00"},
    )

    listed = await auth.fetch(request_json(LIST, method="GET", cookie=current_cookie))
    records = await listed.json()
    assert len(records) == 1
    assert records[0]["current"] is True


async def test_revoke_session_is_owner_scoped_and_generic(adapter, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(sessions, "now", clock.now)
    auth = make_auth(adapter)
    owner = await sign_up(auth, "owner@example.com")
    other = await sign_up(auth, "other@example.com")
    owner_cookie = cookie_pair(owner)
    other_cookie = cookie_pair(other)
    other_row = await adapter.find_one(
        "session",
        [Where("user_id", (await other.json())["user"]["id"])],
    )

    response = await auth.fetch(
        request_json(
            REVOKE,
            {"sessionId": other_row["id"]},
            cookie=owner_cookie,
        )
    )
    assert response.status == 200
    assert await response.json() == {"success": True}
    still_active = await auth.fetch(request_json(GET_SESSION, method="GET", cookie=other_cookie))
    assert (await still_active.json())["session"] is not None


async def test_sensitive_session_management_requires_fresh_session(adapter, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(sessions, "now", clock.now)
    auth = make_auth(adapter, fresh=timedelta(minutes=10))
    signup = await sign_up(auth, "freshness@example.com")
    stale_cookie = cookie_pair(signup)
    clock.advance(minutes=11)

    stale = await auth.fetch(request_json(LIST, method="GET", cookie=stale_cookie))
    assert stale.status == 403
    assert (await stale.json())["title"] == "Session is not fresh; sign in again"

    fresh_cookie = cookie_pair(await sign_in(auth, "freshness@example.com"))
    accepted = await auth.fetch(request_json(LIST, method="GET", cookie=fresh_cookie))
    assert accepted.status == 200


async def test_freshness_and_idle_checks_can_be_explicitly_disabled(adapter, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(sessions, "now", clock.now)
    auth = make_auth(adapter, idle=None, fresh=None)
    signup = await sign_up(auth, "disabled-limits@example.com")
    cookie = cookie_pair(signup)
    clock.advance(days=2)

    listed = await auth.fetch(request_json(LIST, method="GET", cookie=cookie))
    assert listed.status == 200
    assert len(await listed.json()) == 1


async def test_current_session_can_be_revoked_and_clears_cookie(adapter, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(sessions, "now", clock.now)
    auth = make_auth(adapter)
    signup = await sign_up(auth, "current@example.com")
    cookie = cookie_pair(signup)
    current_id = (await adapter.find_one("session", []))["id"]

    revoked = await auth.fetch(request_json(REVOKE, {"sessionId": current_id}, cookie=cookie))
    assert revoked.status == 200
    assert "Max-Age=0" in revoked.headers.get("set-cookie")
    replay = await auth.fetch(request_json(GET_SESSION, method="GET", cookie=cookie))
    assert (await replay.json())["session"] is None


async def test_admin_primitives_are_explicit_and_owner_scoped(adapter, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(sessions, "now", clock.now)
    auth = make_auth(adapter)
    signup = await sign_up(auth, "admin-target@example.com")
    user_id = (await signup.json())["user"]["id"]
    await sign_in(auth, "admin-target@example.com")
    active = await auth.list_user_sessions(user_id)
    assert len(active) == 2
    assert all("token_hash" not in record for record in active)

    assert await auth.revoke_user_session(user_id, active[0]["id"]) == 1
    assert await auth.revoke_user_session("different-user", active[1]["id"]) == 0
    assert await auth.revoke_user_sessions(user_id) == 1


@pytest.mark.parametrize(
    ("path", "method", "data"),
    [
        (LIST, "GET", None),
        (REVOKE, "POST", {"sessionId": "unknown"}),
        (REVOKE_OTHERS, "POST", {}),
        (REVOKE_ALL, "POST", {}),
    ],
)
async def test_session_management_requires_authentication(auth, path, method, data):
    response = await auth.fetch(request_json(path, data, method=method))
    assert response.status == 401


async def test_revoke_session_validates_public_id_after_authentication(adapter, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(sessions, "now", clock.now)
    auth = make_auth(adapter)
    signup = await sign_up(auth, "revoke-input@example.com")
    cookie = cookie_pair(signup)

    for body in ({}, {"sessionId": ""}, {"sessionId": 42}):
        response = await auth.fetch(request_json(REVOKE, body, cookie=cookie))
        assert response.status == 400


@pytest.mark.parametrize(
    "kwargs",
    [
        {"session_ttl": timedelta(0)},
        {"session_idle_timeout": timedelta(0)},
        {"session_touch_interval": timedelta(0)},
        {
            "session_idle_timeout": timedelta(minutes=5),
            "session_touch_interval": timedelta(minutes=5),
        },
        {"session_fresh_ttl": timedelta(0)},
    ],
)
def test_session_configuration_is_validated(adapter, kwargs):
    with pytest.raises(ValueError):
        Auth(
            secret="session-config-test",
            adapter=adapter,
            crypto=ScryptBackend(log_n=12),
            **kwargs,
        )


def test_adapter_without_atomic_update_many_is_rejected():
    with pytest.raises(TypeError):
        Auth(secret="session-adapter-test", adapter=object())
