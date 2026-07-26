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
    legacy_schema = (
        SQLITE_SCHEMA.replace(
            "  last_used_step INTEGER NOT NULL DEFAULT 0,\n",
            "",
        )
        .replace(
            "  last_active_at TEXT NOT NULL,\n",
            "",
        )
        .replace(
            "  grant_id TEXT NOT NULL,\n  scope TEXT,\n  revoked INTEGER NOT NULL DEFAULT 0,\n",
            "  scope TEXT,\n",
        )
        .replace("  grant_id TEXT NOT NULL,\n", "")
        .replace(
            "CREATE INDEX IF NOT EXISTS oauth_code_user_client "
            'ON "oauth_code"(user_id, client_id);\n',
            "",
        )
        .replace(
            "CREATE INDEX IF NOT EXISTS oauth_token_user_client "
            'ON "oauth_token"(user_id, client_id);\n',
            "",
        )
        .replace(
            "  dpop_bound_access_tokens INTEGER NOT NULL DEFAULT 0,\n",
            "",
        )
        .replace("  dpop_jkt TEXT,\n", "")
        .replace(
            "CREATE UNIQUE INDEX IF NOT EXISTS verification_identifier_value_hash\n"
            '  ON "verification"(identifier, value_hash);\n',
            "",
        )
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
    connection.execute(
        'INSERT INTO "session" '
        "(id, token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
        (
            "session-1",
            "session-hash",
            "u1",
            "2026-08-02T00:00:00+00:00",
            "2026-07-26T00:00:00+00:00",
        ),
    )
    connection.execute(
        'INSERT INTO "oauth_client" '
        "(id, client_id, redirect_uris, token_endpoint_auth_method, grant_types, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "client-row",
            "client-1",
            '["https://client.example/cb"]',
            "none",
            '["authorization_code","refresh_token"]',
            "2026-07-26T00:00:00+00:00",
            "2026-07-26T00:00:00+00:00",
        ),
    )
    connection.execute(
        'INSERT INTO "oauth_consent" '
        "(id, user_id, client_id, scope, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (
            "consent-1",
            "u1",
            "client-1",
            "mcp",
            "2026-07-26T00:00:00+00:00",
            "2026-07-26T00:00:00+00:00",
        ),
    )
    connection.execute(
        'INSERT INTO "oauth_code" '
        "(id, code_hash, client_id, user_id, redirect_uri, scope, code_challenge, "
        "code_challenge_method, used, expires_at, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "code-1",
            "code-hash",
            "client-1",
            "u1",
            "https://client.example/cb",
            "mcp",
            "challenge",
            "S256",
            0,
            "2026-07-26T00:05:00+00:00",
            "2026-07-26T00:00:00+00:00",
        ),
    )
    connection.execute(
        'INSERT INTO "oauth_token" '
        "(id, access_token_hash, refresh_token_hash, family_id, client_id, user_id, "
        "scope, access_expires_at, refresh_expires_at, revoked, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "token-1",
            "access-hash",
            "refresh-hash",
            "family-1",
            "client-1",
            "u1",
            "mcp",
            "2026-07-26T01:00:00+00:00",
            "2026-08-26T00:00:00+00:00",
            0,
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
    consent = connection.execute(
        'SELECT grant_id, revoked FROM "oauth_consent" WHERE id = ?', ("consent-1",)
    ).fetchone()
    assert consent == ("consent-1", 0)
    code = connection.execute(
        'SELECT grant_id FROM "oauth_code" WHERE id = ?', ("code-1",)
    ).fetchone()
    token = connection.execute(
        'SELECT grant_id FROM "oauth_token" WHERE id = ?', ("token-1",)
    ).fetchone()
    assert code == ("consent-1",)
    assert token == ("consent-1",)
    session = connection.execute(
        'SELECT last_active_at FROM "session" WHERE id = ?', ("session-1",)
    ).fetchone()
    assert session == ("2026-07-26T00:00:00+00:00",)
