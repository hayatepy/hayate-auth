#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d)"

cleanup() {
  rm -r "${work_dir}"
}
trap cleanup EXIT

existing_tables="$(
  psql -v ON_ERROR_STOP=1 -Atc \
    "select count(*) from pg_tables where schemaname='public'"
)"
if [[ "${existing_tables}" != "0" ]]; then
  echo "PostgreSQL upgrade audit requires an empty isolated database" >&2
  exit 1
fi

mkdir "${work_dir}/base" "${work_dir}/target"
git -C "${repo_dir}" archive v0.9.1 | tar -x -C "${work_dir}/base"
git -C "${repo_dir}" archive v0.10.3 | tar -x -C "${work_dir}/target"
(
  cd "${work_dir}/base"
  uv run --locked python -m hayate_auth generate --dialect postgres
) >"${work_dir}/base.sql"
(
  cd "${work_dir}/target"
  uv run --locked python -m hayate_auth generate --dialect postgres --upgrade-from 0.9.1
) >"${work_dir}/upgrade.sql"
(
  cd "${work_dir}/target"
  uv run --locked python -m hayate_auth generate --dialect postgres
) >"${work_dir}/current.sql"

psql -v ON_ERROR_STOP=1 -f "${work_dir}/base.sql" >/dev/null
psql -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
INSERT INTO "user"
  VALUES (
    'user-1',
    'audit@example.com',
    1,
    NULL,
    NULL,
    '2026-01-01T00:00:00Z',
    '2026-01-01T00:00:00Z'
  );
INSERT INTO "session"
  VALUES (
    'session-1',
    'session-hash',
    'user-1',
    '2027-01-01T00:00:00Z',
    NULL,
    NULL,
    '2026-01-02T00:00:00Z'
  );
INSERT INTO "two_factor"
  VALUES (
    'factor-1',
    'user-1',
    'secret',
    1,
    '2026-01-01T00:00:00Z',
    '2026-01-01T00:00:00Z'
  );
INSERT INTO "oauth_consent"
  VALUES (
    'consent-1',
    'user-1',
    'client-1',
    'mcp',
    '2026-01-01T00:00:00Z',
    '2026-01-01T00:00:00Z'
  );
INSERT INTO "oauth_code"
  VALUES (
    'code-1',
    'code-hash',
    'client-1',
    'user-1',
    'https://client.example/callback',
    'mcp',
    'challenge',
    'S256',
    'https://resource.example/mcp',
    0,
    'family-1',
    '2027-01-01T00:00:00Z',
    '2026-01-01T00:00:00Z'
  );
INSERT INTO "oauth_token"
  VALUES (
    'token-1',
    'access-hash',
    'refresh-hash',
    'family-1',
    'client-1',
    'user-1',
    'mcp',
    'https://resource.example/mcp',
    '2027-01-01T00:00:00Z',
    '2027-02-01T00:00:00Z',
    0,
    '2026-01-01T00:00:00Z'
  );
SQL

psql -v ON_ERROR_STOP=1 -f "${work_dir}/upgrade.sql" >/dev/null
psql -v ON_ERROR_STOP=1 -f "${work_dir}/current.sql" >/dev/null
psql -v ON_ERROR_STOP=1 -f "${work_dir}/current.sql" >/dev/null

test "$(
  psql -Atc "select count(*) from pg_tables where schemaname='public'"
)" = "11"
test "$(
  psql -Atc "select last_active_at from session where id='session-1'"
)" = "2026-01-02T00:00:00Z"
test "$(
  psql -Atc "select last_used_step from two_factor where id='factor-1'"
)" = "0"
test "$(
  psql -Atc \
    "select grant_id || ':' || revoked from oauth_consent where id='consent-1'"
)" = "consent-1:0"
test "$(
  psql -Atc "select grant_id from oauth_code where id='code-1'"
)" = "consent-1"
test "$(
  psql -Atc "select grant_id from oauth_token where id='token-1'"
)" = "consent-1"

echo "PostgreSQL v0.9.1 -> v0.10.3 data-preserving upgrade profile passed"
