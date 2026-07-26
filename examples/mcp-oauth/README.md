# MCP server + OAuth authorization server, one app

The complete AS-mode story (DESIGN §19): hayate-mcp serves MCP and acts as
the OAuth resource server (RFC 9728), hayate-auth issues the tokens (OAuth
2.1 + PKCE, RFC 8414 metadata, RFC 7591 dynamic client registration, and
strict RFC 8707 resource binding), and
the splice between them is one line:

```python
verify_token=auth.oauth_token_verifier(resource=f"{ISSUER}/mcp")
```

## Run it

```sh
uv sync
uv run uvicorn app:app --port 8931
```

Set `VERIFY_MODE=introspection` to make the MCP mount validate every bearer
token through the network endpoint instead of the co-located direct callable.
The acceptance suite uses this mode, so the official MCP client exercises the
separated-resource-server protocol path.

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
It then authenticates as a separated resource server, introspects the same
opaque token, revokes the user's consent, and proves introspection immediately
returns only `{"active": false}`.

## Separate the resource server

The authorization-server app registers a confidential, resource-bound
introspection credential:

```python
from hayate_auth import AuthorizationServer, OAuthResourceServer

authorization_server = AuthorizationServer(
    issuer=ISSUER,
    login_url="/login",
    consent_url="/consent",
    resource=RESOURCE,
    resource_servers=(
        OAuthResourceServer(
            client_id=os.environ["INTROSPECTION_CLIENT_ID"],
            client_secret=os.environ["INTROSPECTION_CLIENT_SECRET"],
            resource=RESOURCE,
        ),
    ),
)
```

The separate MCP process uses the callable in
[`separated_resource_server.py`](separated_resource_server.py):

```python
from hayate_auth import OAuthIntrospectionVerifier

verify_token = OAuthIntrospectionVerifier(
    endpoint=f"{ISSUER}/api/auth/oauth2/introspect",
    client_id=os.environ["INTROSPECTION_CLIENT_ID"],
    client_secret=os.environ["INTROSPECTION_CLIENT_SECRET"],
    resource=RESOURCE,
)
```

Pass it directly to `hayate_mcp.Authorization(verify_token=verify_token)`.
Use a CSPRNG-generated secret of at least 32 characters and HTTPS outside
loopback development. The verifier fails closed on network, authentication,
content-type, JSON, active-state, and audience errors.

## Revoke tokens and consent

- OAuth clients call `POST /api/auth/oauth2/revoke` with form-encoded
  `token` plus their normal token-endpoint authentication.
- A signed-in user calls `GET /api/auth/oauth2/consents` to list active
  grants and `POST /api/auth/oauth2/consents/revoke` with JSON
  `{"client_id": "..."}` to revoke one.
- Existing v0.9.1 databases must apply
  `python -m hayate_auth generate --dialect <dialect> --upgrade-from 0.9.1`
  before running this code.
