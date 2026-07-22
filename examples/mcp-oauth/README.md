# MCP server + OAuth authorization server, one app

The complete AS-mode story (DESIGN §19): hayate-mcp serves MCP and acts as
the OAuth resource server (RFC 9728), hayate-auth issues the tokens (OAuth
2.1 + PKCE, RFC 8414 metadata, RFC 7591 dynamic client registration), and
the splice between them is one line:

```python
verify_token=auth.oauth_token_verifier(resource=f"{ISSUER}/mcp")
```

## Run it

```sh
uv sync
uv run uvicorn app:app --port 8931
```

Connect any MCP client to `http://127.0.0.1:8931/mcp`:

- **MCP Inspector**: `npx @modelcontextprotocol/inspector`, transport
  "Streamable HTTP". The 401 walks it to the AS automatically; sign in /
  sign up on the `/login` page (demo@example.com / demo password 42 are
  pre-filled) and approve on `/consent`.
- **Claude Code**: `claude mcp add --transport http demo http://127.0.0.1:8931/mcp`
  and complete the OAuth prompt.

## Tests

```sh
uv run pytest -q
```

`tests/test_e2e.py` drives the official SDK client (`OAuthClientProvider`)
over real HTTP: 401 discovery -> protected-resource metadata -> AS metadata
-> dynamic registration -> authorization code + PKCE (the login/consent
browser hops are played by an httpx session) -> token -> `tools/call`.
