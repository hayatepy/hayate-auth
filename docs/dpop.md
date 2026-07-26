# Sender-constrained OAuth for MCP resource servers

Status: implemented as an opt-in RFC 9449 profile. The default remains Bearer
so clients implementing the stable MCP authorization specification
(`2025-11-25`) continue to interoperate.

## Decision

hayate-auth uses DPoP rather than mutual TLS as its portable
sender-constraining mechanism.

| Concern | DPoP (RFC 9449) | OAuth mTLS (RFC 8705) |
|---|---|---|
| ASGI | Application-level ES256; no proxy TLS state needed | Requires client-certificate termination and trusted forwarding |
| Cloudflare Workers | WebCrypto verification works in the Python isolate | Certificate enrollment and API Shield are deployment-specific |
| Desktop/public MCP client | Client owns a local key pair | Client certificate provisioning and rotation are operationally heavy |
| Separated resource server | `cnf.jkt` travels through RFC 7662 introspection | Requires certificate-thumbprint propagation and mTLS at every resource |
| Token theft | Stolen token is unusable without the private key | Same property while the client certificate remains protected |

Transport security is still mandatory in production. DPoP does not replace
HTTPS, client authentication, PKCE, or RFC 8707 audience restriction.

## Threat model

DPoP addresses replay of a leaked access token and, for public clients, a
leaked refresh token. It also prevents a compromised resource server from
replaying an audience-restricted token without the client's key.

It does not address:

- an attacker who can invoke the legitimate client's signing key;
- compromise of the authorization or resource server;
- request-body tampering below an already compromised TLS endpoint;
- denial of service against the replay store.

The implementation fails closed when signature verification, introspection,
or replay storage is unavailable.

## Cross-runtime profile

The initial portable algorithm profile is ES256 over P-256:

- CPython/ASGI delegates verification to the optional `cryptography` package
  (`hayate-auth[dpop]`);
- Python Workers delegates verification to `crypto.subtle`;
- RFC 7638 SHA-256 JWK thumbprints are used for `dpop_jkt` and `cnf.jkt`;
- the authorization-server metadata advertises
  `dpop_signing_alg_values_supported: ["ES256"]`.

Each proof is checked for a single `DPoP` header, compact-JWS syntax, duplicate
JSON members, public-key-only JWK data, signature validity, `jti`, `htm`,
query-free `htu`, and a bounded `iat`. Protected-resource proofs also require
the RFC 9449 `ath` access-token hash and a key matching the token's
`cnf.jkt`.

## Binding and rotation

Clients can send `dpop_jkt` at the authorization endpoint. The resulting code
is bound to that thumbprint and can be exchanged only with a proof from the
same key.

The token endpoint:

- returns `token_type: DPoP` for a bound access token;
- stores the thumbprint with the opaque token;
- exposes `token_type: DPoP` and `cnf: {"jkt": ...}` through RFC 7662;
- binds a public client's refresh-token family to the same key;
- rejects public-client key replacement during refresh.

Public-client key rotation therefore requires a new authorization flow. A
confidential client already sender-constrains its refresh token with client
authentication and may select a new access-token DPoP key on a later refresh,
as specified by RFC 9449.

Dynamic registration and Client ID Metadata Documents support
`dpop_bound_access_tokens`. When true, authorization requires `dpop_jkt` and
every token request requires a proof.

## Replay and nonce policy

`AdapterDPoPReplayStore` uses a database `UNIQUE (jkt, jti)` constraint as the
atomic replay boundary. Accepted proofs cost one steady-state `INSERT`;
expired-row cleanup costs one amortized `DELETE` per configured interval.
ASGI replicas and Workers isolates must share the same database. The in-memory
store is for single-process tests and feasibility work only.

The RFC 9449 server-provided nonce mechanism is optional. hayate-auth does not
require it in this profile because:

- a unique `jti`, shared replay store, short proof window, `ath`, and HTTPS
  already prevent ordinary proof replay;
- current official MCP SDK OAuth clients do not implement DPoP nonce retries;
- a nonce adds a challenge round trip and separate per-AS/per-resource state.

A deployment exposed to proof pre-generation by hostile code in the client
context should add nonce enforcement before treating DPoP as protection
against that attacker model. Nonce support must use `use_dpop_nonce`,
`DPoP-Nonce`, and distinct AS/resource-server nonce namespaces; it must never
silently downgrade to a nonce-free proof after issuing a challenge.

## Reproducible cost baseline

Run:

```console
uv run python scripts/benchmark_dpop_replay.py --samples 10000
```

The 2026-07-27 macOS/SQLite run in this repository measured:

| Measure | Result |
|---|---:|
| Accepted proof throughput | 1,803 proofs/s |
| Write latency median / p95 / p99 | 0.4587 / 0.7809 / 2.3686 ms |
| Replay rejection | 0.2308 ms |
| SQLite growth | 364.54 bytes/proof |

These numbers are a local storage baseline, not a D1 latency claim. The
operation count is portable. Measure production D1, Postgres, or Redis latency
in the deployment region before setting an SLO.

## Configuration

Authorization server:

```python
from hayate_auth import AuthorizationServer, DPoPConfig

authorization_server = AuthorizationServer(
    issuer="https://auth.example",
    login_url="/login",
    consent_url="/consent",
    dpop=DPoPConfig(),
)
```

Separated resource server:

```python
from hayate_auth import (
    AdapterDPoPReplayStore,
    DPoPConfig,
    DPoPRequestVerifier,
    OAuthIntrospectionVerifier,
)

introspect = OAuthIntrospectionVerifier(
    endpoint="https://auth.example/api/auth/oauth2/introspect",
    client_id="foliomcp-resource-server",
    client_secret=resource_server_secret,
    resource="https://folio.example/mcp",
)
verify_request = DPoPRequestVerifier(
    verify_token=introspect,
    config=DPoPConfig(),
    replay_store=AdapterDPoPReplayStore(resource_server_adapter),
)
```

Mount it with hayate-mcp's request-aware authorization path:

```python
from hayate_mcp import Authorization

authorization = Authorization(
    resource="https://folio.example/mcp",
    authorization_servers=["https://auth.example"],
    verify_request=verify_request,
    authorization_scheme="DPoP",
    scopes_supported=["mcp"],
    required_scopes=["mcp"],
)
```

The request verifier expects:

```http
Authorization: DPoP <access-token>
DPoP: <proof-jwt>
```

The official MCP Python SDK currently models OAuth token types as Bearer only.
The existing end-to-end example therefore remains the compatibility gate for
the stable MCP specification. DPoP is an opt-in OAuth security extension; a
DPoP-capable MCP client must add `dpop_jkt`, sign token/resource requests, and
reject any token response whose `token_type` is not `DPoP`.

## Executable evidence

- `tests/test_dpop.py`: ASGI signature, request binding, replay, and attack
  regressions;
- `tests/test_authorization_server.py`: authorization-code, access-token,
  public refresh-token, registration, and introspection binding;
- `scripts/check_current_workerd.sh`: real current workerd + WebCrypto + D1,
  including proof replay rejection;
- `examples/mcp-oauth/tests/test_e2e.py`: current official MCP SDK Bearer
  interoperability, proving DPoP support did not break the stable MCP path.

Normative references:

- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)
- [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)
- [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700)
- [MCP authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
