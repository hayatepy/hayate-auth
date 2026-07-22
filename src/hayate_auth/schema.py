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
    "two_factor": ("id", "user_id", "secret", "enabled", "created_at", "updated_at"),
    "api_key": (
        "id",
        "user_id",
        "name",
        "prefix",
        "key_hash",
        "scopes",
        "expires_at",
        "enabled",
        "last_used_at",
        "created_at",
        "updated_at",
    ),
    "oauth_client": (
        "id",
        "client_id",
        "client_secret_hash",
        "name",
        "redirect_uris",
        "token_endpoint_auth_method",
        "grant_types",
        "scope",
        "created_at",
        "updated_at",
    ),
    "oauth_code": (
        "id",
        "code_hash",
        "client_id",
        "user_id",
        "redirect_uri",
        "scope",
        "code_challenge",
        "code_challenge_method",
        "resource",
        "used",
        "family_id",
        "expires_at",
        "created_at",
    ),
    "oauth_token": (
        "id",
        "access_token_hash",
        "refresh_token_hash",
        "family_id",
        "client_id",
        "user_id",
        "scope",
        "resource",
        "access_expires_at",
        "refresh_expires_at",
        "revoked",
        "created_at",
    ),
    "oauth_consent": (
        "id",
        "user_id",
        "client_id",
        "scope",
        "created_at",
        "updated_at",
    ),
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
CREATE TABLE IF NOT EXISTS "two_factor" (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL UNIQUE REFERENCES "user"(id) ON DELETE CASCADE,
  secret TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS "api_key" (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  name TEXT,
  prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  scopes TEXT,
  expires_at TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_used_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS api_key_user_id ON "api_key"(user_id);
CREATE TABLE IF NOT EXISTS "oauth_client" (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL UNIQUE,
  client_secret_hash TEXT,
  name TEXT,
  redirect_uris TEXT NOT NULL,
  token_endpoint_auth_method TEXT NOT NULL,
  grant_types TEXT NOT NULL,
  scope TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS "oauth_code" (
  id TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL UNIQUE,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  scope TEXT,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL DEFAULT 'S256',
  resource TEXT,
  used INTEGER NOT NULL DEFAULT 0,
  family_id TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS "oauth_token" (
  id TEXT PRIMARY KEY,
  access_token_hash TEXT NOT NULL UNIQUE,
  refresh_token_hash TEXT UNIQUE,
  family_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  scope TEXT,
  resource TEXT,
  access_expires_at TEXT NOT NULL,
  refresh_expires_at TEXT,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS oauth_token_family_id ON "oauth_token"(family_id);
CREATE TABLE IF NOT EXISTS "oauth_consent" (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL,
  scope TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (user_id, client_id)
);
"""

# Same shape for PostgreSQL. Timestamps stay ISO-8601 TEXT and booleans stay
# 0/1 integers on purpose: adapters exchange plain strings/ints, so one wire
# format works across sqlite, D1, and postgres without per-dialect casting.
POSTGRES_SCHEMA = SQLITE_SCHEMA

DIALECTS = {"sqlite": SQLITE_SCHEMA, "postgres": POSTGRES_SCHEMA, "d1": SQLITE_SCHEMA}
