# Reproduction procedures

All commands are run from a clean clone of
`https://github.com/hayatepy/hayate-auth`. Record the OS, architecture, tool
versions, command, exit status, and relevant logs in the report. Verify the
target first:

```sh
git fetch --tags --force
git tag -v v0.9.1
test "$(git rev-list -n 1 v0.9.1)" = \
  b8486cf40cfa227b44062ee41bddb4a6b74132fa
uv sync --locked
uv run python scripts/check_audit_pack.py --check
```

The checker downloads the exact PyPI artifacts and official ASVS 5.0.0 CSV,
then verifies their pinned SHA-256 digests. GitHub's release page also exposes
the build provenance and SBOM attestations for the wheel and sdist.

## Profile A: SQLite and ASGI/direct HTTP

Run the full tagged test suite, then both locked acceptance applications:

```sh
uv run pytest -q
(cd examples/todo && uv sync --locked && uv run pytest -q)
(cd examples/mcp-oauth && uv sync --locked && uv run pytest -q)
```

The TODO example covers mounted authentication and SQLite through an ASGI
server. The MCP OAuth example drives dynamic registration, authorization,
consent, PKCE token exchange, bearer-protected MCP initialization and tool
execution with the official MCP Python SDK client.

At minimum retain the selected node IDs in `target.toml` as finding evidence.
Reviewers are expected to add adversarial tests; a green provided suite is not
itself an audit conclusion.

## Profile B: PostgreSQL schema application

hayate-auth v0.9.1 does not ship a PostgreSQL runtime adapter. This profile
only verifies the advertised generated DDL:

```sh
uv run python -m hayate_auth generate --dialect postgres > schema.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f schema.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f schema.sql
psql "$DATABASE_URL" -Atc \
  "select count(*) from pg_tables where schemaname='public';"
```

The expected project-table count in a fresh database is 11. Apply twice to
verify idempotence. Do not characterize this result as query/adapter
compatibility.

## Profile C: Cloudflare workerd and local D1

Use Python 3.13, Node 24, uv, workers-py 1.15.0, and Wrangler:

```sh
bash scripts/check_audit_workerd.sh
```

The script applies the generated D1 schema twice, performs a clean
`pywrangler sync`, boots the Python Worker, verifies authorization-server and
protected-resource metadata, writes a dynamically registered OAuth client to
D1, and confirms unauthenticated resource/MCP requests are rejected.

Cloudflare's local D1 and workerd emulate the runtime and bindings but are not
a production account test. A commissioned reviewer should separately assess
production configuration, secret bindings, database policies, logging, and
rate limiting with the operator.

## Reporting deviations

If a command cannot be reproduced, record it as a deviation rather than
silently substituting a different package, standard version, database, or
runtime. Proposed patches should include a failing regression test and state
which profile(s) were executed after the fix.
