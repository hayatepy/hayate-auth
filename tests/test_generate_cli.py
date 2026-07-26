"""python -m hayate_auth generate"""

import sqlite3

import pytest

from hayate_auth.__main__ import main
from hayate_auth.schema import SQLITE_SCHEMA


def test_generate_sqlite(capsys):
    assert main(["generate", "--dialect", "sqlite"]) == 0
    out = capsys.readouterr().out
    assert 'CREATE TABLE IF NOT EXISTS "user"' in out
    assert 'CREATE TABLE IF NOT EXISTS "verification"' in out
    assert "last_used_step INTEGER NOT NULL DEFAULT 0" in out


def test_generate_d1_matches_sqlite(capsys):
    main(["generate", "--dialect", "d1"])
    d1 = capsys.readouterr().out
    main(["generate", "--dialect", "sqlite"])
    sqlite = capsys.readouterr().out
    assert d1 == sqlite


def test_unknown_dialect_errors():
    with pytest.raises(SystemExit):
        main(["generate", "--dialect", "oracle"])


def test_upgrade_from_091_preserves_existing_two_factor(capsys):
    legacy_schema = SQLITE_SCHEMA.replace(
        "  last_used_step INTEGER NOT NULL DEFAULT 0,\n",
        "",
    )
    connection = sqlite3.connect(":memory:")
    connection.executescript(legacy_schema)
    connection.execute(
        'INSERT INTO "user" '
        "(id, email, email_verified, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        ("u1", "u1@example.com", 1, "2026-07-26T00:00:00+00:00", "2026-07-26T00:00:00+00:00"),
    )
    connection.execute(
        'INSERT INTO "two_factor" '
        "(id, user_id, secret, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (
            "f1",
            "u1",
            "SECRET",
            1,
            "2026-07-26T00:00:00+00:00",
            "2026-07-26T00:00:00+00:00",
        ),
    )

    assert main(["generate", "--dialect", "sqlite", "--upgrade-from", "0.9.1"]) == 0
    migration = capsys.readouterr().out
    connection.executescript(migration)
    row = connection.execute(
        'SELECT enabled, last_used_step FROM "two_factor" WHERE id = ?', ("f1",)
    ).fetchone()
    assert row == (1, 0)
