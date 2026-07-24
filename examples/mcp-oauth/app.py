"""An MCP server and its OAuth authorization server in one hayate app.

This is the full DESIGN §19 story: hayate-mcp is the RFC 9728 resource
server, hayate-auth's AS mode issues the tokens, and the splice is one
line — ``verify_token=auth.oauth_token_verifier(resource=...)``.

    uv run uvicorn app:app --port 8931

Then point any MCP client at http://127.0.0.1:8931/mcp — it will discover
the AS via the 401 + protected-resource metadata, register itself (RFC
7591), and walk the browser through /login and /consent.

Demo credentials are seeded on first run: demo@example.com / demo password 42
"""

import os

import mcp.types as types
from hayate import Context, Hayate
from hayate_mcp import Authorization, McpMount
from mcp.server.lowlevel import Server

from hayate_auth import Auth, AuthorizationServer
from hayate_auth.adapters.sqlite import SQLiteAdapter

ISSUER = os.environ.get("ISSUER", "http://127.0.0.1:8931")
RESOURCE = f"{ISSUER}/mcp"

adapter = SQLiteAdapter(os.environ.get("AUTH_DB", ":memory:"))
adapter.create_tables()

auth = Auth(
    secret=os.environ.get("AUTH_SECRET", "dev-secret-not-for-production"),
    adapter=adapter,
    authorization_server=AuthorizationServer(
        issuer=ISSUER,
        login_url="/login",
        consent_url="/consent",
        scopes_supported=("mcp",),
        resource=RESOURCE,
    ),
)

server = Server("hayate-oauth-demo")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="echo",
            description="Echo the input back (requires an OAuth token).",
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


app = Hayate()
auth.register(app)
McpMount(
    server,
    path="/mcp",
    stateless=True,
    authorization=Authorization(
        resource=RESOURCE,
        authorization_servers=[ISSUER],
        verify_token=auth.oauth_token_verifier(resource=RESOURCE),
        scopes_supported=["mcp"],
    ),
).register(app)


LOGIN_HTML = """<!doctype html>
<meta charset="utf-8"><title>Sign in</title>
<body style="font-family:system-ui;max-width:24rem;margin:4rem auto">
<h1>Sign in</h1>
<form id="f">
  <input name="email" type="email" value="demo@example.com" style="width:100%;margin:.25rem 0">
  <input name="password" type="password" value="demo password 42"
         style="width:100%;margin:.25rem 0">
  <button>Sign in</button> <button type="button" id="up">Sign up</button>
</form>
<p id="msg"></p>
<script>
const q = new URLSearchParams(location.search);
async function call(path) {
  const data = Object.fromEntries(new FormData(document.getElementById("f")));
  const res = await fetch("/api/auth" + path, {
    method: "POST",
    headers: {"content-type": "application/json"},
    body: JSON.stringify(data),
  });
  if (res.ok) location.href = q.get("redirect") || "/";
  else document.getElementById("msg").textContent = (await res.json()).title || res.status;
}
document.getElementById("f").addEventListener("submit", e => {
  e.preventDefault();
  call("/sign-in/email");
});
document.getElementById("up").addEventListener("click", () => call("/sign-up/email"));
</script>
"""

CONSENT_HTML = """<!doctype html>
<meta charset="utf-8"><title>Authorize access</title>
<body style="font-family:system-ui;max-width:24rem;margin:4rem auto">
<h1>Authorize access</h1>
<p><b id="who"></b> wants access<span id="scopes"></span>.</p>
<button id="ok">Approve</button> <button id="no">Deny</button>
<script>
const q = new URLSearchParams(location.search);
document.getElementById("who").textContent = q.get("client_name") || q.get("client_id");
if (q.get("scope")) document.getElementById("scopes").textContent = " to: " + q.get("scope");
async function decide(accept) {
  const res = await fetch("/api/auth/oauth2/consent", {
    method: "POST",
    headers: {"content-type": "application/json"},
    body: JSON.stringify({accept}),
  });
  const body = await res.json();
  if (res.ok) location.href = body.redirect_uri;
  else document.body.textContent = body.title || res.status;
}
document.getElementById("ok").addEventListener("click", () => decide(true));
document.getElementById("no").addEventListener("click", () => decide(false));
</script>
"""


@app.get("/login")
async def login_page(c: Context):
    return c.html(LOGIN_HTML)


@app.get("/consent")
async def consent_page(c: Context):
    return c.html(CONSENT_HTML)


@app.get("/")
async def home(c: Context):
    return c.json({"mcp_endpoint": "/mcp", "authorization_server": ISSUER})
