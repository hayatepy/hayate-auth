# hayate-auth

Standards-first authentication for [hayate](https://github.com/hayatepy/hayate) —
a mountable, better-auth-style auth handler built on the WHATWG Request/Response
model.

> **Status: design phase.** Nothing installable yet. The internal design memo
> (Japanese, per project convention) lives in [DESIGN.md](DESIGN.md).

## Why

- Python has no equivalent of better-auth: a framework-agnostic, self-hosted,
  schema-owning auth *library*. django-allauth is Django-only; fastapi-users is
  in maintenance mode.
- better-auth works on every JS framework because its core is a single
  `fetch(Request) -> Response` handler. hayate is the only Python framework
  whose user-facing surface *is* WHATWG Request/Response — so that architecture
  finally maps 1:1 to Python.
- Zero-dependency core (its only dependency is hayate, itself zero-dependency),
  standards-first (OAuth 2.1 + PKCE, Fetch Metadata CSRF, RFC 6265bis cookies,
  TOTP RFC 6238, WebAuthn), designed to run unchanged on ASGI servers *and*
  Cloudflare Python Workers.

## Planned shape

```python
from hayate import Hayate
from hayate_auth import Auth
from hayate_auth.adapters.sqlite import SQLiteAdapter

auth = Auth(secret=..., adapter=SQLiteAdapter("app.db"))

app = Hayate()
auth.register(app)  # serves /api/auth/* (sign-up, sign-in, session, ...)

@app.get("/me", auth.require_session())
async def me(c):
    return c.json(c.get("user"))
```

## License

MIT
