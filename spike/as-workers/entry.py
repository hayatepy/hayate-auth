"""AS mode + MCP server in ONE Worker: disposable spike (DESIGN §19).

Findings land in docs/research/authorization-server.md. This is the
edge-complete form of the story: hayate-auth issues OAuth tokens, the
hayate-mcp mount verifies them, both in a single workerd isolate over D1.

Everything env-dependent is built lazily on the first request: deployed
Workers run the global scope through a deploy-time validator that has NO
bindings or vars attached (production finding: module-level ``env.DB``
fails validation with ``AttributeError: DB``), while local ``pywrangler
dev`` tolerates global access — a real trap.

Repro (Windows: run from a C: copy — pywrangler traps in research/kdf.md;
mcp needs the wasm-platform manual vendor from hayate-mcp research/pyodide.md):

    uv sync
    uv run python -m hayate_auth generate --dialect d1 > schema.sql
    npx wrangler d1 execute AUTH_DB --local --file schema.sql
    UV_PYTHON_DOWNLOADS=automatic UV_PYTHON_PREFERENCE=managed uv run pywrangler dev
    # (on Windows the vendor silently fails: redo it by hand)
    uv pip install --python .venv --python-platform wasm32-pyodide2025 \
      --python-version 3.13 --target python_modules --no-build \
      -r pylock.toml --preview-features pylock
    printf '1.15.0' > python_modules/.synced && printf '1.15.0' > .venv-workers/.synced
    UV_PYTHON_DOWNLOADS=automatic UV_PYTHON_PREFERENCE=managed uv run pywrangler dev

Production: create a real D1, point wrangler.toml at it, set
``[vars] ISSUER = "https://<name>.<subdomain>.workers.dev"``, apply the
schema with ``--remote``, then ``uv run pywrangler deploy``.
"""

from hayate import Context, Hayate
from hayate.adapters.workers import to_workers
from workers import env

from hayate_auth import Auth, AuthorizationServer, ScryptBackend
from hayate_auth.adapters.d1 import D1Adapter

app = Hayate()

_auth: Auth | None = None


def get_auth() -> Auth:
    global _auth
    if _auth is None:
        issuer = getattr(env, "ISSUER", None) or "http://127.0.0.1:8787"
        # Functional acceptance profiles can lower the KDF cost explicitly so
        # a constrained local workerd stays focused on the protocol under test.
        # With no spike-only variable, deployed applications retain the secure
        # Auth default (scrypt log_n=17).
        spike_log_n = getattr(env, "HAYATE_AUTH_SPIKE_KDF_LOG_N", None)
        crypto = ScryptBackend(log_n=int(spike_log_n)) if spike_log_n else None
        _auth = Auth(
            secret="spike-secret-not-for-production",
            adapter=D1Adapter(env.DB),
            crypto=crypto,
            authorization_server=AuthorizationServer(
                issuer=issuer,
                login_url="/login",
                consent_url="/consent",
                scopes_supported=("mcp",),
            ),
        )
    return _auth


@app.on("GET", "/api/auth/*")
@app.on("POST", "/api/auth/*")
async def auth_routes(c: Context):
    return await get_auth().fetch(c.req)


@app.get("/.well-known/oauth-authorization-server")
async def as_metadata(c: Context):
    return await get_auth().fetch(c.req)


@app.get("/protected")
async def protected(c: Context):
    """A bare Bearer-protected route (the §3 measurement), kept for contrast."""
    auth = get_auth()
    issuer = auth.authorization_server.issuer
    header = c.req.headers.get("authorization") or ""
    scheme, _, credential = header.partition(" ")
    claims = None
    if scheme.lower() == "bearer" and credential:
        claims = await auth.verify_oauth_token(credential.strip(), resource=f"{issuer}/protected")
    if claims is None:
        return c.json({"title": "Authorization required"}, status=401)
    return c.json({"ok": True, "user_id": claims["user_id"], "scopes": claims["scopes"]})


def build_server():
    # Workers use hayate-mcp's SDK-independent runtime: the official SDK's
    # Pydantic dependency has no supported Pyodide wheel. ASGI continues to
    # use McpMount + the official SDK; this edge profile verifies the same
    # 2025-11-25 wire protocol through WorkerMcpMount.
    from hayate_mcp import WorkerMcpServer

    server = WorkerMcpServer("hayate-as-workers", version="0.9.1")

    @server.tool(
        name="echo",
        description="Echo the input back (OAuth-protected, on workerd).",
        input_schema={
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
            "additionalProperties": False,
        },
        execution={"taskSupport": "forbidden"},
    )
    async def echo(arguments: dict) -> str:
        return f"echo: {arguments['text']}"

    return server


def get_mount():
    from hayate_mcp import Authorization, WorkerMcpMount

    mount = getattr(app, "_mcp_mount", None)
    if mount is None:
        auth = get_auth()
        issuer = auth.authorization_server.issuer
        resource = f"{issuer}/mcp"
        mount = WorkerMcpMount(
            build_server(),
            path="/mcp",
            authorization=Authorization(
                resource=resource,
                authorization_servers=[issuer],
                verify_token=auth.oauth_token_verifier(resource=resource),
                scopes_supported=["mcp"],
            ),
        )
        app._mcp_mount = mount
    return mount


@app.on("GET", "/mcp")
@app.on("POST", "/mcp")
@app.on("DELETE", "/mcp")
async def mcp_route(c: Context):
    return await get_mount().fetch(c.req)


@app.get("/.well-known/oauth-protected-resource/mcp")
async def protected_resource_metadata(c: Context):
    # RFC 9728 §3.1 path-insertion form (hayate-mcp >= 0.6.0).
    return await get_mount().fetch(c.req)


Default = to_workers(app)
