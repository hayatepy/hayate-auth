# Changelog

All notable changes to hayate-auth are documented here.

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
