"""Current-workerd acceptance app for RFC 9449 DPoP over D1."""

from hayate import Context, Hayate
from hayate.adapters.workers import to_workers
from workers import env

from hayate_auth import (
    AdapterDPoPReplayStore,
    Auth,
    AuthorizationServer,
    DPoPConfig,
    DPoPRequestVerifier,
)
from hayate_auth.adapters.d1 import D1Adapter

app = Hayate()
_auth: Auth | None = None
_dpop_verifier: DPoPRequestVerifier | None = None


def get_auth() -> Auth:
    global _auth
    if _auth is None:
        issuer = getattr(env, "ISSUER", None) or "http://127.0.0.1:8787"
        require_dpop = getattr(env, "REQUIRE_DPOP", "false") == "true"
        _auth = Auth(
            secret="spike-secret-not-for-production",
            adapter=D1Adapter(env.DB),
            authorization_server=AuthorizationServer(
                issuer=issuer,
                login_url="/login",
                consent_url="/consent",
                scopes_supported=("mcp",),
                dpop=DPoPConfig(require_bound_tokens=require_dpop),
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
    """Bearer compatibility route; DPoP verification is covered separately."""
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


@app.get("/dpop-protected")
async def dpop_protected(c: Context):
    global _dpop_verifier
    auth = get_auth()
    issuer = auth.authorization_server.issuer
    resource = f"{issuer}/dpop-protected"
    if _dpop_verifier is None:
        _dpop_verifier = DPoPRequestVerifier(
            verify_token=auth.oauth_token_verifier(resource=resource),
            config=DPoPConfig(),
            replay_store=AdapterDPoPReplayStore(auth.adapter),
        )
    claims = await _dpop_verifier(c.req)
    if claims is None:
        return c.json({"title": "Authorization required"}, status=401)
    return c.json({"ok": True, "user_id": claims["user_id"]})


Default = to_workers(app)
