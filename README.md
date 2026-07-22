# hayate-auth

Standards-first authentication for [hayate](https://github.com/hayatepy/hayate) —
a mountable, better-auth-style auth handler built on the WHATWG Request/Response
model.

> **Status: alpha (0.2.x).** Email+password, sessions, CSRF, email
> verification, and password reset are implemented and attack-regression-tested;
> a `generate` CLI and a Cloudflare D1 adapter ship too. OAuth (PKCE) is next,
> gated on `hayate-fetch` reaching PyPI. Not yet security-audited — see
> [SECURITY.md](SECURITY.md). The internal design memo (Japanese) lives in
> [DESIGN.md](DESIGN.md).

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

Email delivery is your callback (`send_reset_password` / `send_verification_email`);
the core mints and verifies tokens but never builds URLs or sends mail. Generate
migration DDL with `python -m hayate_auth generate --dialect sqlite|postgres|d1`.

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

## License

MIT
