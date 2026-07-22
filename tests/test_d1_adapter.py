"""D1Adapter against an in-process fake of the D1 prepare/bind/all API,
backed by a real sqlite3 database — the SQL itself is exercised for real."""

import sqlite3

import pytest

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


async def test_operators_sort_limit(adapter):
    for i in range(1, 4):
        await adapter.create("user", _user(i))
    newest = await adapter.find_many("user", [], sort=("created_at", "desc"), limit=1)
    assert newest[0]["id"] == "u3"
    chosen = await adapter.find_many("user", [Where("id", ["u1", "u3"], "in")])
    assert {r["id"] for r in chosen} == {"u1", "u3"}


async def test_identifier_validation_still_applies(adapter):
    with pytest.raises(ValueError):
        await adapter.create("user", {"evil": 1})
