# Reproduction procedures

All commands begin in a clean clone of
`https://github.com/hayatepy/hayate-auth`. Record the audit-pack commit, OS,
architecture, tool versions, command, exit status, and relevant logs in the
report. Do not run target tests from the mutable audit-pack checkout.

## Verify and isolate the review target

Check out the audit-pack commit recorded on
[`hayate-auth#14`](https://github.com/hayatepy/hayate-auth/issues/14), then:

```sh
git fetch --tags --force
git tag -v v0.9.1
git tag -v v0.10.3
test "$(git rev-list -n 1 v0.9.1)" = \
  b8486cf40cfa227b44062ee41bddb4a6b74132fa
test "$(git rev-list -n 1 v0.10.3)" = \
  20dd7ae08c12051d23fdbe4b242578f800dacdfc
uv sync --locked
uv run python scripts/check_audit_pack.py --check
git diff --stat v0.9.1..v0.10.3
test "$(git diff --name-only v0.10.2..v0.10.3 -- src/hayate_auth)" = \
  src/hayate_auth/__init__.py
```

The checker downloads the exact base/current PyPI artifacts, the v0.10.3 SPDX
SBOM, and the official ASVS 5.0.0 CSV, then verifies their pinned SHA-256
digests. It also validates both tag signatures against the committed
maintainer key, collects selected tests from each exported tagged tree, and
rejects stale public current-target references. The final `git diff` assertion
proves that v0.10.3 changes only the public version constant under the package
source after the v0.10.2 security fix.

Create a detached worktree so every runtime profile executes the exact current
review target:

```sh
review_root="$(pwd)"
worktree_parent="$(mktemp -d)"
target_dir="$worktree_parent/target"
git worktree add --detach "$target_dir" v0.10.3
cd "$target_dir"
uv sync --locked
```

## Profile A: SQLite and direct/ASGI HTTP

From the detached v0.10.3 worktree, run the full target suite and both locked
acceptance applications:

```sh
uv run pytest -q
(cd examples/todo && uv sync --locked && uv run pytest -q)
(cd examples/mcp-oauth && uv sync --locked && uv run pytest -q)
```

The TODO example covers mounted authentication and SQLite through an ASGI
server. The MCP OAuth example drives dynamic registration, authorization,
consent, PKCE token exchange, bearer-protected MCP initialization, and tool
execution with the official MCP Python SDK client. The main suite also drives
the same framework-independent `fetch(Request) -> Response` surface directly.

At minimum retain the base and amendment node IDs as finding evidence.
Reviewers are expected to add adversarial tests; a green provided suite is not
itself an audit conclusion.

## Profile B: PostgreSQL schema application

hayate-auth v0.10.3 does not ship a PostgreSQL runtime adapter. This profile
only verifies the advertised generated DDL:

```sh
uv run python -m hayate_auth generate --dialect postgres > schema.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f schema.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f schema.sql
psql "$DATABASE_URL" -Atc \
  "select count(*) from pg_tables where schemaname='public';"
```

The expected project-table count in a fresh database is 11. Apply twice to
verify idempotence. Against a second, empty, isolated database, run the
data-preserving upgrade profile:

```sh
(cd "$review_root" && \
  PGDATABASE=hayate_auth_upgrade_audit \
  bash scripts/check_audit_postgres_upgrade.sh)
```

The script refuses a database that already contains public tables. It exports
the signed v0.9.1 tree, applies its schema, inserts representative session,
TOTP, consent, code, and token rows, applies the cumulative v0.10.3 upgrade,
and verifies every security-state backfill plus the 11-table current schema.
Do not characterize these results as PostgreSQL query/adapter compatibility.

## Profile C: stable MCP Bearer path on workerd/D1

Use Python 3.13, Node 24, uv, workers-py 1.15.0, and Wrangler:

```sh
bash scripts/check_audit_workerd.sh
```

The script applies the generated D1 schema twice, performs a clean
`pywrangler sync`, boots the Python Worker, verifies authorization-server and
protected-resource metadata, writes a dynamically registered OAuth client to
D1, and confirms unauthenticated resource/MCP requests are rejected. This is
the stable MCP `2025-11-25` Bearer compatibility profile.

## Profile D: v0.10.3 security delta on workerd/D1

Run the current-wheel acceptance from the same detached target:

```sh
bash scripts/check_current_workerd.sh
```

This builds the v0.10.3 wheel, installs it into a real Python Worker bundle,
and exercises D1-backed common-password rejection, TOTP replay rejection,
OAuth issuance/revocation, consent management, and RFC 9449 DPoP proof
verification/replay rejection through WebCrypto.

Cloudflare's local D1 and workerd emulate the runtime and bindings but are not
a production account test. A commissioned reviewer should separately assess
production configuration, secret bindings, database policies, logging, TLS,
tenant isolation, backups, and rate limiting with the operator.

After retaining evidence, remove the detached target from the original clone:

```sh
cd "$review_root"
git worktree remove "$target_dir"
rmdir "$worktree_parent"
```

## Reporting deviations

If a command cannot be reproduced, record it as a deviation rather than
silently substituting a different target, package, standard version, database,
or runtime. Proposed patches should include a failing regression test and
state which profile(s) were executed after the fix.
