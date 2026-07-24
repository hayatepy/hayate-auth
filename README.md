# hayate-auth

Standards-first authentication for [hayate](https://github.com/hayatepy/hayate) —
a mountable, better-auth-style auth handler built on the WHATWG Request/Response
model.

> **Status: alpha (0.8.x).** Email+password, sessions, CSRF, email
> verification, password reset, **OAuth 2.1 + PKCE** (Google / GitHub), **TOTP
> two-factor**, **API keys**, an **OAuth 2.1 authorization server** (AS
> mode: RFC 8414 metadata, RFC 7591 dynamic registration, MCP Client ID
> Metadata Documents, PKCE-only code + refresh grants), **magic links**, and
> **passkeys** (WebAuthn L3, `[passkey]`
> extra) are implemented and attack-regression-tested; a `generate` CLI, a
> plugin API, and a Cloudflare D1 adapter ship too. Not yet security-audited —
> see [SECURITY.md](SECURITY.md). The internal design memo (Japanese) lives in
> [DESIGN.md](DESIGN.md); release history is in
> [CHANGELOG.md](CHANGELOG.md).

```python
import os

from hayate import Hayate
from hayate_auth import Auth
from hayate_auth.adapters.sqlite import SQLiteAdapter

adapter = SQLiteAdapter("app.db")
adapter.create_tables()

auth = Auth(secret=os.environ["AUTH_SECRET"], adapter=adapter)

app = Hayate()
auth.register(app)  # serves /api/auth/* (sign-up, sign-in, session, ...)

@app.get("/me", auth.require_session())
async def me(c):
    return c.json(c.get("user"))
```

The same file runs under any ASGI server and on Cloudflare Python Workers —
see [examples/todo](examples/todo).

## Endpoints

| Method / path (under `/api/auth`) | Purpose |
|---|---|
| POST `/sign-up/email` | Register with email + password, start a session |
| POST `/sign-in/email` | Verify credentials, start a session |
| GET `/get-session` | Current `{user, session}` (or nulls) |
| POST `/sign-out` | Revoke the session server-side |
| POST `/forget-password` → `/reset-password` | Reset flow via a one-shot hashed token |
| GET `/verify-email` | Confirm an email with a one-shot token |
| POST `/sign-in/social` → GET `/callback/:provider` | OAuth 2.1 + PKCE (Google / GitHub) |
| POST `/two-factor/enable` · `/verify` · `/disable` | TOTP (RFC 6238) enrollment |
| POST `/sign-in/two-factor` | Second step when 2FA is on |
| POST `/api-key/create` · `/verify` · `/delete` · GET `/api-key/list` | API keys (hashed, scoped, expiring) |
| GET `/oauth2/authorize` · POST `/oauth2/consent` · `/oauth2/token` · `/oauth2/register` | AS mode: OAuth 2.1 authorization server |
| POST `/sign-in/magic-link` → GET `/magic-link/verify` | Magic links (plugin) |
| POST `/passkey/generate-register-options` · `/verify-registration` · `/generate-authenticate-options` · `/verify-authentication` · GET `/passkey/list-user-passkeys` · POST `/passkey/delete-passkey` | Passkeys (WebAuthn L3, `[passkey]` extra) |

Magic links ship as the first `AuthPlugin` — plugins add routes with the
same handler signature the built-ins use:

```python
from hayate_auth.plugins import magic_link

auth = Auth(
    secret=..., adapter=adapter,
    plugins=[magic_link(send=deliver_link_email)],  # async (email, token) -> None
)
```

Passkeys need the extra (`pip install hayate-auth[passkey]`, pulls
py_webauthn) and a relying-party config:

```python
from hayate_auth import PasskeyConfig

auth = Auth(
    secret=..., adapter=adapter,
    passkey=PasskeyConfig(rp_id="example.com", rp_name="My App",
                          origin="https://example.com"),
)
```

## AS mode: be the OAuth authorization server

Pass an `AuthorizationServer` config and your app *issues* OAuth 2.1 tokens —
authorization-code + PKCE (S256 only), refresh rotation with reuse detection,
RFC 8414 metadata at `/.well-known/oauth-authorization-server`, and open
RFC 7591 dynamic client registration (what MCP clients expect). Tokens are
opaque and stored hashed; login and consent pages stay yours (`login_url` /
`consent_url`), the consent decision is one JSON POST.

```python
from hayate_auth import Auth, AuthorizationServer

auth = Auth(
    secret=os.environ["AUTH_SECRET"],
    adapter=adapter,
    authorization_server=AuthorizationServer(
        issuer="https://app.example.com",
        login_url="/login",
        consent_url="/consent",
        scopes_supported=("mcp",),
        resource="https://app.example.com/mcp",
    ),
)
```

Paired with [hayate-mcp](https://github.com/hayatepy/hayate-mcp)'s resource
server, that is an **MCP server and its authorization server in one app** —
the flow MCP Inspector and Claude Code drive end to end
([examples/mcp-oauth](examples/mcp-oauth)):

```python
from hayate_mcp import Authorization, McpMount
McpMount(server, authorization=Authorization(
    resource="https://app.example.com/mcp",
    authorization_servers=["https://app.example.com"],
    verify_token=auth.oauth_token_verifier(resource="https://app.example.com/mcp"),
)).register(app)
```

MCP 2025-11-25 recommends Client ID Metadata Documents before DCR. Enable
them with an injected fetcher so your deployment controls DNS and egress:

```python
from hayate_auth import ClientIdMetadataDocuments

authorization_server = AuthorizationServer(
    # issuer/login_url/consent_url/scopes_supported/resource as above
    client_id_metadata_documents=ClientIdMetadataDocuments(
        fetch_client_metadata,  # async URL -> hayate.Response; must reject redirects
        allow_url=outbound_client_policy,
    ),
)
```

hayate-auth validates HTTPS URL-form client IDs, exact `client_id`, same-origin
or loopback redirects, public-client metadata, JSON content type, and a 5 KiB
body limit. The fetcher remains responsible for DNS-level SSRF protection.

API keys are the lighter-weight bridge to the same resource server —
`verify_token=auth.verify_api_key` protects an MCP server with a static key
instead of the full OAuth dance.

REST and generated OpenAPI share the same authorization declaration:

```python
from hayate_openapi import OpenApi

@app.get("/documents", auth.require_oauth_token(
    "documents:read", resource="https://app.example.com/mcp"
))
async def documents(c):
    return c.json({"subject": c.get("principal")["subject"]})

OpenApi(
    app,
    title="API",
    version="1",
    security_schemes=auth.openapi_security_schemes(),
)
```

With TOTP enabled, `/sign-in/email` returns `{"two_factor_required": true}` plus
a short-lived signed challenge cookie instead of a session; the client then
posts the authenticator code to `/sign-in/two-factor` to get the session — so a
stolen password alone never signs in.

Email delivery is your callback (`send_reset_password` / `send_verification_email`);
the core mints and verifies tokens but never builds URLs or sends mail. Generate
migration DDL with `python -m hayate_auth generate --dialect sqlite|postgres|d1`.

OAuth providers are injected; the token exchange runs over
[hayate-fetch](https://github.com/hayatepy/hayate-fetch), so it works on ASGI
and Workers alike:

```python
from hayate_auth import Auth, google, github

auth = Auth(
    secret=os.environ["AUTH_SECRET"],
    adapter=adapter,
    providers=[
        google(client_id=..., client_secret=...),
        github(client_id=..., client_secret=...),
    ],
)
```

## Why

- Python has no equivalent of better-auth: a framework-agnostic, self-hosted,
  schema-owning auth *library*. django-allauth is Django-only; fastapi-users is
  in maintenance mode.
- better-auth works on every JS framework because its core is a single
  `fetch(Request) -> Response` handler. hayate is the only Python framework
  whose user-facing surface *is* WHATWG Request/Response — so that architecture
  finally maps 1:1 to Python.
- Zero-dependency core (its only dependency is hayate, itself zero-dependency).
  Databases, KDFs, and email are injected protocols.

## Security posture

- Passwords: scrypt at OWASP parameters (N=2^17, r=8, p=1) on every runtime,
  PBKDF2-HMAC-SHA256 (600k) fallback; PHC-style strings make the backends
  mutually verifiable. Length-only policy per NIST SP 800-63B.
- Sessions: opaque 256-bit tokens, only their SHA-256 stored;
  `__Host-`-prefixed HttpOnly SameSite=Lax cookies on HTTPS.
- CSRF: SameSite + Origin (RFC 6454) + Fetch Metadata — no token embedding.
- Sign-in failures are uniform in body and KDF timing (enumeration defense).
- Coverage ledger: [docs/asvs.md](docs/asvs.md) (OWASP ASVS V6/V7, ratcheted).
- **You must rate-limit** `/api/auth/*` (hayate middleware or your
  infrastructure): brute-force throttling is deliberately out of core.
- Authorization-server adapters must implement atomic `update_many()` and
  return the affected-row count. This prevents concurrent authorization-code
  or refresh-token redemption from minting multiple token families.

## License

MIT
