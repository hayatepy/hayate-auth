# Login-protected TODO — the v0.1 acceptance app

The same `app.py` runs on an ASGI server and on Cloudflare Python Workers.

## Test (no server)

```sh
uv sync
uv run pytest
```

## Run under uvicorn

```sh
uv run uvicorn app:app --reload
```

```sh
curl -X POST localhost:8000/api/auth/sign-up/email -H 'content-type: application/json' \
  -d '{"email": "me@example.com", "password": "long enough"}' -D -
curl localhost:8000/todos -H 'cookie: hayate_auth.session=<token from Set-Cookie>'
```

## Run on local workerd

`uv run pywrangler dev` once hayate-auth is on PyPI. Until then pywrangler
cannot resolve the path dependency (it locks against PyPI — see the Known
traps in the hayate CLAUDE.md), so hand-vendor: install `hayate` into
`python_modules/` and copy `src/hayate_auth` next to it. Verified working
2026-07-22 — wasm scrypt, sqlite, sessions, and the 401 guard all run on
workerd unchanged.

Storage caveats on Workers: this example keeps todos in isolate memory and
auth state in an in-memory SQLite — both reset whenever the isolate recycles.
Durable storage lands with the D1 adapter (roadmap).
