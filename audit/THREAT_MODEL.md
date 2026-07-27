# Threat model for hayate-auth v0.10.1

This is the current threat model for the signed v0.10.1 review target. The
signed v0.9.1 target remains the immutable review base; the security-relevant
range and residual risks are summarized in
`amendments/v0.10.1.md`.

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
5. A co-located or separated MCP resource server accepts only tokens verified
   for its exact RFC 8707 resource. A separated server relies on an
   independently provisioned introspection credential.
6. Opt-in DPoP relies on a client-held P-256 private key and a replay store
   shared by every authorization/resource-server replica or Worker isolate.

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
- A faulty or adversarial adapter violates guarded-update or uniqueness
  atomicity and causes multiple sessions/token families to be minted, a TOTP
  step or proof to be replayed, or revoked state to be revived.
- A compromised resource-server credential attempts cross-resource token
  introspection; a stolen Bearer or DPoP token is replayed against a different
  method, URL, audience, or client key.
- A supply-chain attacker tampers with a release artifact, dependency,
  workflow, or audit evidence.

## Implemented control boundaries

Passwords use salted scrypt or PBKDF2-HMAC-SHA256. Raw session,
verification/magic-link/reset, API-key, OAuth code/access/refresh, and dynamic
client-secret values are not stored; only digests are persisted. Sessions are
server-side reference tokens and rotate on authentication. HTTPS cookies use
`__Host-`, Secure, HttpOnly, and SameSite=Lax. Origin and Fetch Metadata checks
protect cookie-carried state changes.

OAuth authorization codes are short-lived, single-use,
client/redirect/resource bound, and require PKCE S256. Refresh tokens rotate
with family reuse detection. RFC 7009 revocation and end-user consent
revocation invalidate complete token families without disclosing whether
foreign material exists. RFC 7662 introspection authenticates a separately
registered resource server and exposes active state only for its exact
resource. Consent generations make revocation win against concurrent code or
refresh issuance.

Sessions enforce absolute and inactivity expiry, bound activity-write
frequency, fresh-session checks for management, owner-scoped revocation, and
responses that never expose token material. TOTP persists the last accepted
time step behind a guarded atomic update. Every password-establishment path
uses one normalized common/compromised-password policy and fails closed by
default when its optional checker is unavailable.

Opt-in RFC 9449 DPoP binds authorization codes, access tokens, public-client
refresh families, introspection results, and resource requests to an ES256
key. Proof parsing, time/method/URL/access-token binding, and shared replay
storage fail closed. Bearer remains the default MCP compatibility profile.
Passkeys bind origin, RP ID, purpose, and challenge and reject counter
regression. Security regression evidence for the base and current delta is
enumerated in `target.toml` and `amendments/v0.10.1.toml`.

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

## Residual and accepted/delegated risks

- Credential stuffing, password guessing, and malicious dynamic registration
  require external per-IP and per-account throttling. The core deliberately
  has no process-local limiter because it would not coordinate across Workers.
- The built-in common-password set is a deterministic offline baseline.
  Deployments needing a current breach corpus must inject a privacy-preserving
  checker and choose the documented availability policy.
- DPoP is opt-in and the default Bearer profile remains replayable if a token
  is exposed. The DPoP profile does not implement server-provided nonce
  challenges; clients vulnerable to hostile proof pre-generation need an
  additional nonce policy before claiming protection from that attacker.
- ASVS sender-constraint coverage applies only when
  `DPoPConfig.require_bound_tokens=True` and every resource uses
  `DPoPRequestVerifier`. The default interoperability profile remains Bearer
  and must not be presented as sender-constrained.
- DPoP replay safety requires all replicas/isolates to use the same atomic
  persistence boundary. The in-memory replay store is not a multi-replica
  production control.
- Session management exposes secure API primitives, not a user interface.
  Administrative revocation methods deliberately rely on the embedding
  application's authorization policy.
- Email magic links are a documented convenience authenticator, not an ASVS
  Level 3 factor; `v5.0.0-6.3.6` explicitly excludes email authentication at
  that level.
- Provider OAuth ID-token claim handling relies on the documented OAuth/OIDC
  provider contract and TLS-bound token exchange. Reviewers should evaluate
  that boundary and the account-linking rules as a high-priority design area.

## Review priorities

The independent review should prioritize authentication bypass; adapter
atomicity and uniqueness under concurrency; TOTP/session/consent/revocation
races; OAuth 2.1/RFC 9700 behavior; DPoP proof parsing, binding and replay;
CIMD and redirect validation; token-family state transitions; CSRF/cookie
assumptions; secret storage; migration correctness; D1/workerd behavior; and
differences between direct/ASGI and Worker execution. Findings should
distinguish library defects from required deployment controls.
