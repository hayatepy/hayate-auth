# Changelog

All notable changes to hayate-auth are documented here.

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
