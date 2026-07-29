# Independent security audit pack

This directory makes an independent review of hayate-auth reproducible. It
does not claim that the project is certified by OWASP or that an external
audit has already happened.

## Base and current review target

`current.toml` defines the active review without rewriting history:

- The signed `v0.9.1` tag at
  `b8486cf40cfa227b44062ee41bddb4a6b74132fa` is the immutable base recorded in
  `target.toml`.
- The signed `v0.10.3` tag at
  `20dd7ae08c12051d23fdbe4b242578f800dacdfc` is the current review target
  recorded in `amendments/v0.10.3.toml`. The v0.10.0 and v0.10.1 amendments
  are retained as intermediate historical targets.

The base pins its published wheel, source distribution, and the official
OWASP ASVS 5.0.0 CSV. The amendment pins the current wheel, source
distribution, and SPDX SBOM. All remote inputs are fixed by SHA-256. The
checker exports both tagged trees into disposable directories and collects
each target's selected evidence tests there, so later development on `main`
cannot silently replace review evidence.

Reviewers should start with:

- `THREAT_MODEL.md` for assets, trust boundaries, adversaries, and known gaps.
- `amendments/v0.10.3.md` for the security-relevant delta and residual risks.
- `../docs/asvs.md` for the selected ASVS 5.0.0 control ledger.
- `PROCEDURES.md` for the exact SQLite/direct/ASGI, PostgreSQL
  schema/migration, and workerd/D1 reproduction profiles.
- `RFP.md` for deliverables, independence requirements, and disclosure terms.
- `PROPOSAL_TEMPLATE.md` for a comparable proposal response and maintainer
  award record without publishing commercial or vulnerability details.

Run `uv run python scripts/check_audit_pack.py --check` from the repository
root. This verifies both signed targets, release artifact/SBOM hashes, the
official ASVS source hash and requirement IDs, evidence references, current
ledger counts, public current-target references, and this pack's deterministic
manifest.

## Product scope

In scope are the framework-independent `fetch(Request) -> Response` auth core,
SQLite and D1 adapters, session and CSRF behavior, email/password and recovery
flows, provider OAuth client mode, TOTP, magic link, passkeys, API keys,
OAuth authorization-server/resource-server integration, revocation,
introspection, consent management, and opt-in DPoP.

PostgreSQL is represented only by generated schema DDL. hayate-auth does not
ship a PostgreSQL runtime adapter, so the audit profile verifies that the DDL
applies idempotently to PostgreSQL; it must not be reported as adapter
coverage. Deployment infrastructure, mail delivery, UI, TLS termination,
database encryption, and rate limiting are integration responsibilities.

## Target history rule

Never silently move an active review to a new commit. Add a new amendment,
obtain the reviewer's written agreement, point `current.toml` to it, regenerate
`manifest.json`, and retain the old amendment, report, and release identity so
findings remain traceable. The manifest authenticates the current pack; signed
tags and pinned artifact digests authenticate the immutable code targets.
