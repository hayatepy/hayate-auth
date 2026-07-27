# Security Policy

hayate-auth is **alpha software and has not received an external security
audit**. Do not run it as the sole protection for production credentials yet.
The immutable v0.9.1 review base, current v0.10.1 amendment, threat model,
reproducible environment profiles, and reviewer RFP are in
[`audit/`](audit/README.md).

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on this repository
(Security → Report a vulnerability). Reports are acknowledged within 72 hours.
Please do not open public issues for suspected vulnerabilities.

## Scope and design commitments

- No self-built cryptographic primitives: all KDF/HMAC work goes through
  `hashlib` / `hmac` / WebCrypto (DESIGN §8).
- Passwords are stored as salted scrypt (OWASP parameters) or
  PBKDF2-HMAC-SHA256 (600k) PHC strings; sessions are stored only as SHA-256
  digests of 256-bit random tokens.
- Verification/magic-link/reset values, API keys, OAuth authorization codes,
  access/refresh tokens, and dynamic client secrets are also stored only as
  digests.
- TOTP seeds and upstream OAuth provider access/refresh tokens are
  intentionally recoverable. A database reader can expose them. Production
  deployments must provide least-privilege database access, encryption at
  rest and in backups, access auditing, and rotation/revocation procedures.
- Attack regressions (session fixation, replay after sign-out, expiry,
  enumeration timing, CSRF) are part of the test suite and never removed.
- Rate limiting is explicitly the embedding application's responsibility;
  deployments must throttle `/api/auth/*`, especially password, magic-link,
  reset, TOTP, and dynamic-registration endpoints.

## Known limitations

Rate limiting, a current breach-corpus service, production secret/database
controls, and administrative authorization remain deployment
responsibilities. DPoP sender constraints are opt-in so stable Bearer MCP
clients remain compatible, and the supported profile does not implement DPoP
nonce challenges. Email magic links are not an ASVS Level 3 factor.
PostgreSQL coverage is generated schema DDL only; hayate-auth does not ship a
PostgreSQL runtime adapter. See the [threat model](audit/THREAT_MODEL.md) and
[ASVS 5.0.0 ledger](docs/asvs.md) for exact boundaries.

## Review triggers

Re-scope an independent review before a production-trust release whenever a
change alters cryptographic/KDF parameters, recoverable-secret storage,
session or token formats, authentication factors, OAuth/MCP protocol behavior,
adapter atomicity, or a runtime/database trust boundary. Review the threat
model and ASVS source at least annually even without such a change. A new audit
target must identify a new immutable commit; an old report never silently
applies to later code.
