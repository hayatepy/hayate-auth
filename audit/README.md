# Independent security audit pack

This directory makes an independent review of hayate-auth reproducible. It
does not claim that the project is certified by OWASP or that an external
audit has already happened.

## Frozen target

The review target is the signed `v0.9.1` tag at commit
`b8486cf40cfa227b44062ee41bddb4a6b74132fa`. `target.toml` also pins the
published wheel, source distribution, and official OWASP ASVS 5.0.0 CSV by
SHA-256. The checker exports the tagged tree into a disposable directory and
collects its evidence tests there, so later development on `main` cannot
silently replace the reviewed evidence and does not need to stop while the
independent engagement is active.

Reviewers should start with:

- `THREAT_MODEL.md` for assets, trust boundaries, adversaries, and known gaps.
- `../docs/asvs.md` for the selected ASVS 5.0.0 control ledger.
- `PROCEDURES.md` for the exact SQLite/ASGI, PostgreSQL schema, and
  workerd/D1 reproduction profiles.
- `RFP.md` for deliverables, independence requirements, and disclosure terms.

Run `uv run python scripts/check_audit_pack.py --check` from the repository
root. This verifies the signed target, release artifact hashes, official ASVS
source hash and requirement IDs, evidence references, ledger counts, and this
pack's deterministic manifest.

## Product scope

In scope are the framework-independent `fetch(Request) -> Response` auth core,
SQLite and D1 adapters, session and CSRF behavior, email/password and recovery
flows, provider OAuth client mode, TOTP, magic link, passkeys, API keys, and
OAuth authorization-server/resource-server integration.

PostgreSQL is represented only by generated schema DDL. hayate-auth does not
ship a PostgreSQL runtime adapter, so the audit profile verifies that the DDL
applies idempotently to PostgreSQL; it must not be reported as adapter
coverage. Deployment infrastructure, mail delivery, UI, TLS termination,
database encryption, and rate limiting are integration responsibilities.

## Updating the target

Never silently move an active review to a new commit. Add a new target version,
obtain the reviewer's written agreement, regenerate `manifest.json`, and retain
the old report and target so findings remain traceable.
