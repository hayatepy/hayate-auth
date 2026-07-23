"""AS mode + MCP server in ONE Worker: disposable spike (DESIGN §19).

Findings land in docs/research/authorization-server.md. This is the
edge-complete form of the story: hayate-auth issues OAuth tokens, the
hayate-mcp mount verifies them, both in a single workerd isolate over D1.

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
"""

from hayate import Context, Hayate
from hayate.adapters.workers import to_workers
from workers import env

from hayate_auth import Auth, AuthorizationServer
from hayate_auth.adapters.d1 import D1Adapter

ISSUER = "http://127.0.0.1:8787"
MCP_RESOURCE = f"{ISSUER}/mcp"

auth = Auth(
    secret="spike-secret-not-for-production",
    adapter=D1Adapter(env.DB),
    authorization_server=AuthorizationServer(
        issuer=ISSUER,
        login_url="/login",
        consent_url="/consent",
        scopes_supported=("mcp",),
    ),
)

app = Hayate()
auth.register(app)


@app.get("/protected")
async def protected(c: Context):
    """A bare Bearer-protected route (the §3 measurement), kept for contrast."""
    header = c.req.headers.get("authorization") or ""
    scheme, _, credential = header.partition(" ")
    claims = None
    if scheme.lower() == "bearer" and credential:
        claims = await auth.verify_oauth_token(credential.strip(), resource=f"{ISSUER}/protected")
    if claims is None:
        return c.json({"title": "Authorization required"}, status=401)
    return c.json({"ok": True, "user_id": claims["user_id"], "scopes": claims["scopes"]})


def build_server():
    # mcp is imported lazily: its jsonschema/rpds chain seeds entropy at
    # import, which workerd forbids at Worker global scope (hayate-mcp
    # examples/workers pins this pattern).
    import mcp.types as types
    from mcp.server.lowlevel import Server

    server = Server("hayate-as-workers")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="echo",
                description="Echo the input back (OAuth-protected, on workerd).",
                inputSchema={
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                },
            )
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
        return [types.TextContent(type="text", text=f"echo: {arguments['text']}")]

    return server


def get_mount():
    from hayate_mcp import Authorization, McpMount

    mount = getattr(app, "_mcp_mount", None)
    if mount is None:
        mount = McpMount(
            build_server(),
            path="/mcp",
            stateless=True,
            authorization=Authorization(
                resource=MCP_RESOURCE,
                authorization_servers=[ISSUER],
                verify_token=auth.oauth_token_verifier(resource=MCP_RESOURCE),
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
