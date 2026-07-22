"""The four models hayate-auth owns (DESIGN §4), and their SQLite DDL.

Column names are the single source of truth: adapters validate every
model/field against this table, which is also what makes the naive SQL
composition in the sqlite adapter injection-safe.
"""

from __future__ import annotations

MODELS: dict[str, tuple[str, ...]] = {
    "user": ("id", "email", "email_verified", "name", "image", "created_at", "updated_at"),
    "session": (
        "id",
        "token_hash",
        "user_id",
        "expires_at",
        "ip_address",
        "user_agent",
        "created_at",
    ),
    "account": (
        "id",
        "user_id",
        "provider_id",
        "account_id",
        "password_hash",
        "access_token",
        "refresh_token",
        "expires_at",
        "created_at",
        "updated_at",
    ),
    "verification": ("id", "identifier", "value_hash", "expires_at", "created_at"),
}

SQLITE_SCHEMA = """\
CREATE TABLE IF NOT EXISTS "user" (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  email_verified INTEGER NOT NULL DEFAULT 0,
  name TEXT,
  image TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS "session" (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS session_user_id ON "session"(user_id);
CREATE TABLE IF NOT EXISTS "account" (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  password_hash TEXT,
  access_token TEXT,
  refresh_token TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (provider_id, account_id)
);
CREATE INDEX IF NOT EXISTS account_user_id ON "account"(user_id);
CREATE TABLE IF NOT EXISTS "verification" (
  id TEXT PRIMARY KEY,
  identifier TEXT NOT NULL,
  value_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
"""

# Same shape for PostgreSQL. Timestamps stay ISO-8601 TEXT and booleans stay
# 0/1 integers on purpose: adapters exchange plain strings/ints, so one wire
# format works across sqlite, D1, and postgres without per-dialect casting.
POSTGRES_SCHEMA = SQLITE_SCHEMA

DIALECTS = {"sqlite": SQLITE_SCHEMA, "postgres": POSTGRES_SCHEMA, "d1": SQLITE_SCHEMA}
