"""AS mode on workerd: OAuth 2.1 AS + D1, disposable spike (DESIGN §19).

Findings land in docs/research/authorization-server.md.

Repro (Windows: run from a C: copy — pywrangler traps in research/kdf.md):

    uv sync
    uv run python -m hayate_auth generate --dialect d1 > schema.sql
    npx wrangler d1 execute AUTH_DB --local --file schema.sql
    UV_PYTHON_DOWNLOADS=automatic UV_PYTHON_PREFERENCE=managed uv run pywrangler dev

Then walk the flow with curl (sign-up -> DCR -> authorize -> consent ->
token -> GET /protected with the Bearer).
"""

from hayate import Context, Hayate
from hayate.adapters.workers import to_workers
from workers import env

from hayate_auth import Auth, AuthorizationServer
from hayate_auth.adapters.d1 import D1Adapter

ISSUER = "http://127.0.0.1:8787"

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
    """The RS half without hayate-mcp: the same verifier an McpMount gets."""
    header = c.req.headers.get("authorization") or ""
    scheme, _, credential = header.partition(" ")
    claims = None
    if scheme.lower() == "bearer" and credential:
        claims = await auth.verify_oauth_token(credential.strip(), resource=f"{ISSUER}/protected")
    if claims is None:
        return c.json({"title": "Authorization required"}, status=401)
    return c.json({"ok": True, "user_id": claims["user_id"], "scopes": claims["scopes"]})


Default = to_workers(app)
