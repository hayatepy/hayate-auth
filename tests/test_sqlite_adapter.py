"""The reference Adapter: CRUD, operators, and identifier validation."""

import pytest

from hayate_auth.adapter import Where


async def make_user(adapter, i: int):
    await adapter.create(
        "user",
        {
            "id": f"u{i}",
            "email": f"u{i}@example.com",
            "email_verified": 0,
            "name": None,
            "image": None,
            "created_at": f"2026-07-2{i}T00:00:00+00:00",
            "updated_at": f"2026-07-2{i}T00:00:00+00:00",
        },
    )


async def test_crud_round_trip(adapter):
    await make_user(adapter, 1)
    row = await adapter.find_one("user", [Where("id", "u1")])
    assert row["email"] == "u1@example.com"

    updated = await adapter.update("user", [Where("id", "u1")], {"name": "Ada"})
    assert updated["name"] == "Ada"

    assert await adapter.delete("user", [Where("id", "u1")]) == 1
    assert await adapter.find_one("user", [Where("id", "u1")]) is None


async def test_update_many_is_a_guarded_atomic_transition(adapter):
    await make_user(adapter, 1)
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


async def test_operators_and_sort_and_limit(adapter):
    for i in range(1, 4):
        await make_user(adapter, i)

    newer = await adapter.find_many(
        "user", [Where("created_at", "2026-07-21T00:00:00+00:00", "gt")]
    )
    assert {row["id"] for row in newer} == {"u2", "u3"}

    chosen = await adapter.find_many("user", [Where("id", ["u1", "u3"], "in")])
    assert {row["id"] for row in chosen} == {"u1", "u3"}

    ordered = await adapter.find_many("user", [], sort=("created_at", "desc"), limit=2)
    assert [row["id"] for row in ordered] == ["u3", "u2"]


async def test_unknown_identifiers_raise(adapter):
    with pytest.raises(ValueError):
        await adapter.find_one("nope", [])
    with pytest.raises(ValueError):
        await adapter.find_one("user", [Where("evil; DROP TABLE user", "x")])
    with pytest.raises(ValueError):
        await adapter.create("user", {"evil": 1})
    with pytest.raises(ValueError):
        await adapter.find_many("user", [], sort=("id", "sideways"))


async def test_unique_email_is_enforced(adapter):
    await make_user(adapter, 1)
    with pytest.raises(Exception):  # noqa: B017 - sqlite3.IntegrityError
        await adapter.create(
            "user",
            {
                "id": "u9",
                "email": "u1@example.com",
                "email_verified": 0,
                "name": None,
                "image": None,
                "created_at": "2026-07-22T00:00:00+00:00",
                "updated_at": "2026-07-22T00:00:00+00:00",
            },
        )
