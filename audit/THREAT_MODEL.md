# Threat model for hayate-auth v0.9.1

## Security objectives and assets

hayate-auth must prevent an unauthenticated or incorrectly authorized party
from acquiring a user session, API-key identity, OAuth grant, or protected MCP
capability. Assets include password verifiers, session tokens, verification
tokens, API keys, OAuth codes and tokens, client secrets, TOTP seeds, passkey
public keys and counters, upstream OAuth tokens, consent records, and user
identifiers.

Availability controls matter because password hashing and open dynamic client
registration consume resources. Rate limiting is intentionally outside this
library, so a deployment without endpoint throttling does not meet the
documented security profile.

## Trust boundaries

1. The browser or OAuth client sends untrusted HTTP data into Hayate's WHATWG
   Request/Response boundary.
2. hayate-auth validates that data and calls an adapter through a narrow CRUD
   protocol. Adapter atomicity is a security boundary for one-time code and
   refresh-token consumption.
3. SQLite or Cloudflare D1 persists security state. Operators control database
   access, backups, encryption, retention, and tenant isolation.
4. Provider OAuth endpoints, email delivery, reverse proxies, TLS, clocks,
   WebAuthn authenticators, and rate limiters are external trust dependencies.
5. A co-located MCP resource server accepts only tokens verified for its exact
   RFC 8707 resource.

The workerd profile exercises the Worker, D1 binding, authorization server,
and MCP resource server in one isolate. The ASGI profile exercises the same
tagged core over a conventional Python server boundary. These profiles are not
claims about every possible embedding application.

## Adversaries and abuse cases

- A remote attacker performs credential stuffing, password guessing, user
  enumeration, CSRF, token guessing, replay, redirect manipulation, OAuth
  code interception, client/resource confusion, refresh races, and malicious
  dynamic registration.
- A malicious authenticated user crosses owner or scope boundaries, deletes
  another user's key/passkey, widens OAuth scope, or replays another user's
  consent/challenge.
- A database reader attempts offline password cracking or reuse of raw
  session, verification, API-key, authorization-code, access-token,
  refresh-token, or client-secret values.
- A compromised upstream identity provider supplies unverified identity data
  in an account-linking attempt.
- A faulty or adversarial adapter violates guarded-update atomicity and causes
  multiple token families to be minted.
- A supply-chain attacker tampers with a release artifact, dependency,
  workflow, or audit evidence.

## Implemented control boundaries

Passwords use salted scrypt or PBKDF2-HMAC-SHA256. Raw session,
verification/magic-link/reset, API-key, OAuth code/access/refresh, and dynamic
client-secret values are not stored; only digests are persisted. Sessions are
server-side reference tokens and rotate on authentication. HTTPS cookies use
`__Host-`, Secure, HttpOnly, and SameSite=Lax. Origin and Fetch Metadata checks
protect cookie-carried state changes.

OAuth authorization codes are short-lived, single-use, client/redirect/resource
bound, and require PKCE S256. Refresh tokens rotate with family reuse
detection, resource servers enforce audience and scope, and token responses
use `Cache-Control: no-store`. Passkeys bind origin, RP ID, purpose, and
challenge and reject counter regression. Security regression evidence is
enumerated in `target.toml`.

## Recoverable secrets and database compromise

Not every secret is hashed. TOTP seeds must remain recoverable so the server
can calculate codes. Upstream OAuth provider access and refresh tokens are also
stored recoverably because an embedding application may need to call the
provider. A database read can therefore expose those values. Deployments must
use least-privilege database access, encryption at rest and in backups,
auditing, rotation/revocation procedures, and—where the risk assessment
requires it—application-level envelope encryption supplied outside this
release. The `AUTH_SECRET` and provider client secrets must be held in the
deployment's secret manager, not in source or D1 variables committed to Git.

## Known gaps and accepted/delegated risks

- Credential stuffing, password guessing, and malicious dynamic registration
  require external per-IP and per-account throttling. The core deliberately
  has no process-local limiter because it would not coordinate across Workers.
- TOTP verification accepts the same valid time-step code more than once.
  ASVS `v5.0.0-6.5.1` is not met for TOTP until the accepted step is persisted
  and atomically consumed.
- Password registration does not check a top-3000 or breached-password corpus
  (`v5.0.0-6.2.4`, `v5.0.0-6.2.12`).
- Sessions enforce absolute expiry but not inactivity timeout, active-session
  listing, or user-driven revoke-others (`v5.0.0-7.3.1`,
  `v5.0.0-7.5.2`).
- The authorization server has no end-user token/consent revocation or
  introspection endpoint (`v5.0.0-10.4.9`, `v5.0.0-10.7.3`), and it does not
  issue sender-constrained access tokens (`v5.0.0-10.3.5`,
  `v5.0.0-10.4.14`).
- Email magic links are a documented convenience authenticator, not an ASVS
  Level 3 factor; `v5.0.0-6.3.6` explicitly excludes email authentication at
  that level.
- Provider OAuth ID-token claim handling relies on the documented OAuth/OIDC
  provider contract and TLS-bound token exchange. Reviewers should evaluate
  that boundary and the account-linking rules as a high-priority design area.

## Review priorities

The independent review should prioritize authentication bypass, adapter
atomicity under concurrency, OAuth 2.1/RFC 9700 behavior, CIMD and redirect
validation, token-family state transitions, CSRF/cookie assumptions, secret
storage, D1/workerd behavior, and differences between direct/ASGI and Worker
execution. Findings should distinguish library defects from required
deployment controls.
