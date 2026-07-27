# OAuth revocation, introspection, and consent management

The authorization server supports immediate revocation for both deployment
shapes:

- a co-located resource server calls `auth.oauth_token_verifier(resource=...)`;
- a separated resource server calls the RFC 7662 endpoint through
  `OAuthIntrospectionVerifier`.

Both paths use the same opaque, hash-at-rest access tokens. JWT and JWKS are
not required.

The immutable v0.9.1 audit base records these endpoints as absent at that
commit. The v0.10.0 amendment records this implementation and its test
evidence without rewriting the historical target.

## Authorization-server configuration

```python
import os

from hayate_auth import Auth, AuthorizationServer, OAuthResourceServer

resource = "https://mcp.example.com/mcp"
auth = Auth(
    secret=os.environ["AUTH_SECRET"],
    adapter=adapter,
    authorization_server=AuthorizationServer(
        issuer="https://auth.example.com",
        login_url="/login",
        consent_url="/consent",
        scopes_supported=("mcp",),
        resource=resource,
        resource_servers=(
            OAuthResourceServer(
                client_id="mcp-production",
                client_secret=os.environ["INTROSPECTION_CLIENT_SECRET"],
                resource=resource,
            ),
        ),
    ),
)
```

`OAuthResourceServer` credentials are separate from OAuth client
credentials. Each credential can inspect only tokens minted for its exact
RFC 8707 resource. Generate a unique secret with at least 32 characters,
store it in the deployment secret manager, and rotate it as an operational
credential.

When at least one resource server is configured, RFC 8414 metadata advertises
`introspection_endpoint` and `client_secret_basic`. The RFC 7009
`revocation_endpoint` and its supported client authentication methods are
always advertised.

## Separated MCP resource server

```python
from hayate_auth import OAuthIntrospectionVerifier
from hayate_mcp import Authorization

verify_token = OAuthIntrospectionVerifier(
    endpoint="https://auth.example.com/api/auth/oauth2/introspect",
    client_id="mcp-production",
    client_secret=os.environ["INTROSPECTION_CLIENT_SECRET"],
    resource="https://mcp.example.com/mcp",
)

authorization = Authorization(
    resource="https://mcp.example.com/mcp",
    authorization_servers=["https://auth.example.com"],
    verify_token=verify_token,
    scopes_supported=["mcp"],
    required_scopes=["mcp"],
)
```

The verifier rejects the bearer token on every network, HTTP, media-type,
JSON, inactive-state, subject, scope, or audience failure. HTTP is accepted
only for loopback development.

## Endpoint behavior

`POST /api/auth/oauth2/revoke` uses
`application/x-www-form-urlencoded`. Send `token`, optionally
`token_type_hint`, and authenticate exactly as at the token endpoint. Public
clients send `client_id`; confidential clients use their registered Basic or
form authentication method.

Revocation is idempotent. A valid request returns an empty HTTP 200 for a
revoked, unknown, or foreign token, so the endpoint cannot be used to scan
token validity. Revoking either access or refresh material invalidates the
complete token family.

`POST /api/auth/oauth2/introspect` also uses form encoding and requires the
resource-server HTTP Basic credential. Active access tokens return standard
RFC 7662 claims including `client_id`, `scope`, `sub`, `aud`, `iss`, `exp`,
`iat`, and `jti`. Every inactive, unknown, expired, revoked, or
wrong-resource token returns only:

```json
{"active": false}
```

Revocation, introspection, token, and consent-management responses use
`Cache-Control: no-store` and `Pragma: no-cache`.

## End-user consent management

A signed-in user can:

- `GET /api/auth/oauth2/consents` — list active client names, IDs, scopes,
  and timestamps without token material;
- `POST /api/auth/oauth2/consents/revoke` with
  `{"client_id": "..."}` — revoke that user's entire grant to the client.

Consent revocation updates the grant generation before invalidating
authorization codes and token families. Code exchange and refresh rotation
recheck that generation after token insertion. Consequently, a concurrent
request cannot disclose a credential that remains active after revocation,
including on D1 where the adapter operations are separate statements.

## Upgrade from v0.9.1

Apply the explicit migration before deploying the new package:

```sh
python -m hayate_auth generate \
  --dialect sqlite \
  --upgrade-from 0.9.1 > hayate-auth-upgrade.sql
```

Use `postgres` or `d1` for the other supported stores. The migration preserves
existing TOTP enrollments, consents, codes, and token families, backfills
their grant generation, and creates user/client lookup indexes. As with every
hayate-auth migration, the library prints DDL but never mutates production
schema automatically.
