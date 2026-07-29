# Changelog

All notable changes to hayate-auth are documented here.

## Unreleased

## [0.10.2] - 2026-07-30

### Security

- Bind session, OAuth state, authorization consent, passkey challenge, and
  two-factor challenge cookie acceptance to the request scheme. HTTPS now
  accepts only the corresponding `__Host-` cookie name; plain HTTP retains
  only the bare-name fallback for local development.
- Synchronize the public `hayate_auth.__version__` value with the distribution
  version.
- Advance the independent-review target to signed v0.10.1, retain the v0.10.0
  amendment as history, and promote the configured server-wide DPoP
  sender-constraint row to test-backed ASVS coverage.

## [0.10.1] - 2026-07-27

### Security

- Preserve signed v0.9.1 as the independent-review base and add signed v0.10.0
  as a separately pinned current amendment, including release artifacts, SPDX
  SBOM, delta threat model, current ASVS evidence, and tag-isolated
  reproduction procedures. Add a PostgreSQL gate that preserves and verifies
  representative security state across the v0.9.1-to-v0.10.0 migration.
- Prove `DPoPConfig(require_bound_tokens=True)` prevents Bearer issuance even
  for clients that did not opt in individually, including authorization,
  code-exchange, public refresh, resource-binding, and replay evidence on both
  CPython and a second real workerd/WebCrypto + D1 isolate.

## [0.10.0] - 2026-07-27

### Added

- Add RFC 7009 token revocation, RFC 7662 confidential resource-server
  introspection, RFC 8414 discovery metadata, and a fail-closed
  `OAuthIntrospectionVerifier` for
  [separated MCP resource servers](docs/oauth-revocation-introspection.md).
- Add authenticated end-user consent listing and revocation APIs.
- Add one injectable `PasswordPolicy` for sign-up, reset, and authenticated
  password change, with a normalized local common-password baseline, a bounded
  asynchronous breach checker, and Better Auth-compatible change-password
  request fields.
- Add independently enforced session inactivity expiry, bounded atomic
  activity touches, fresh-session-protected listing and revocation endpoints,
  and explicit administrative session revocation primitives.
- Add an opt-in RFC 9449 DPoP profile across authorization-code, access-token,
  public refresh-token, RFC 7662 introspection, ASGI, and Python Workers
  runtimes, with ES256 delegated to `cryptography` or WebCrypto.

### Security

- Reject reuse of an accepted TOTP time step, including concurrent redemption
  and older adjacent-window codes, with a guarded atomic adapter transition.
- Bind authorization codes and tokens to a versioned consent grant so consent
  revocation wins against concurrent code exchange and refresh rotation.
- Revoke complete token families without disclosing whether an unknown or
  foreign token exists; restrict introspection results to the authenticated
  resource server's exact RFC 8707 resource.
- Add explicit SQLite/PostgreSQL/D1 migration DDL for the persisted
  `last_used_step` replay boundary and versioned OAuth consent grants.
- Apply the same password decision before every credential mutation. External
  checker failures fail closed by default without creating users, changing
  credentials, or consuming reset tokens; fail-open behavior requires an
  explicit configuration choice.
- Store no session token material in management responses, scope user-driven
  revocation by both session and owner, and make concurrent revocation win
  against an in-flight activity touch.
- Bind DPoP authorization codes and public refresh-token families to an RFC
  7638 thumbprint, reject token/proof/key replay, and persist proof identifiers
  behind a database uniqueness boundary shared by replicas and isolates.

## [0.9.1] - 2026-07-26

### Changed

- Link the canonical ecosystem start page, production golden app, and tested
  compatibility evidence from the published package description.

## [0.9.0] - 2026-07-24

### Security

- Close the authorization-code and refresh-rotation mint-gap race with
  durable family-compromise markers and guarded finalization. A replay
  observed while a replacement token is being inserted now burns the family
  before either request can disclose valid credentials.
- Upgrade the optional passkey stack to `webauthn` 3.x and its current
  `cryptography` / `pyOpenSSL` security line. Replace the abandoned
  `soft-webauthn` test dependency with an in-repository virtual authenticator
  that still exercises real WebAuthn verification.
- Refuse redirects by default for OAuth token and user-information requests,
  preventing provider credentials or bearer tokens from reaching an
  unexpected origin.
- Audit locked dependencies on every change and publish an SPDX SBOM plus
  GitHub build and SBOM attestations with each release.

## [0.8.0] - 2026-07-24

### Added

- Add MCP 2025-11-25 Client ID Metadata Document discovery with injected
  fetching, URL policy hooks, bounded JSON documents, public-client
  validation, caching, and discovery metadata.
- Add a common `Principal`, RFC 6750 Bearer middleware, scoped API-key and
  OAuth-token guards, OpenAPI security-scheme export, and `LazyAuth` for
  request-bound Workers resources.
- Add strict RFC 8707 MCP resource binding across authorization, code
  exchange, refresh, and token verification.

### Changed

- Authorization-code consumption and refresh-token rotation now use a single
  guarded database update, following better-auth's atomic credential
  consumption model. Custom adapters used in authorization-server mode must
  implement `update_many()` and return the affected-row count.
- MCP-mode issuers, resources, and redirect URIs now require HTTPS outside
  loopback development.
- Harden OAuth endpoint parsing: token requests require form encoding,
  registration requires JSON, unsupported client-auth schemes are rejected,
  and issuer/resource/redirect URIs cannot contain credentials or malformed
  authorities.
- Mark the distribution as typed and run strict mypy validation in CI.

## [0.7.1] - 2026-07-24

### Changed

- Add a complete public release history and current documentation links.
- Harden releases with protected tag-only publishing, tag/version validation,
  and automatic GitHub Release creation after PyPI succeeds.
- Refresh package metadata to describe the current authentication surface.

## [0.7.0] - 2026-07-23

### Added

- Magic-link authentication as the first `AuthPlugin`.
- The public plugin API, with API keys migrated to the same route model.
- Passkeys using WebAuthn Level 3 through the optional `[passkey]` extra.

## [0.6.0] - 2026-07-23

### Added

- OAuth 2.1 authorization-server mode: RFC 8414 metadata, RFC 7591 dynamic
  client registration, PKCE-only authorization code grants, refresh rotation,
  reuse detection, and RFC 8707 resource binding.
- End-to-end interoperability with the official MCP SDK OAuth client.

## [0.5.0] - 2026-07-23

### Added

- Hashed, scoped, expiring API keys and `Auth.verify_api_key()`.
- Integration coverage using an API key to protect a hayate-mcp resource
  server.

## [0.4.0] - 2026-07-23

### Added

- RFC 6238 TOTP two-factor enrollment and two-step sign-in.

## [0.3.0] - 2026-07-23

### Added

- OAuth 2.1 authorization-code flows with PKCE for Google and GitHub.
- Runtime-portable token exchange through hayate-fetch.

## [0.2.0] - 2026-07-23

### Added

- Email verification and password-reset flows.
- Migration DDL generation and the Cloudflare D1 adapter.

## [0.1.0] - 2026-07-22

### Added

- Email-and-password registration and sign-in, sessions, CSRF protection, and
  the SQLite adapter.
- Attack-regression coverage and the first OWASP ASVS V6/V7 ledger.
