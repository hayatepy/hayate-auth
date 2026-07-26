"""Authorization wiring when the MCP resource server is a separate process."""

import os

from hayate_mcp import Authorization

from hayate_auth import OAuthIntrospectionVerifier

AUTHORIZATION_SERVER = os.environ.get("AUTHORIZATION_SERVER", "http://127.0.0.1:8931")
RESOURCE = os.environ.get("MCP_RESOURCE", "http://127.0.0.1:8941/mcp")

verify_token = OAuthIntrospectionVerifier(
    endpoint=f"{AUTHORIZATION_SERVER}/api/auth/oauth2/introspect",
    client_id=os.environ.get("INTROSPECTION_CLIENT_ID", "mcp-resource-server"),
    client_secret=os.environ.get(
        "INTROSPECTION_CLIENT_SECRET",
        "dev-introspection-secret-change-me",
    ),
    resource=RESOURCE,
)

authorization = Authorization(
    resource=RESOURCE,
    authorization_servers=[AUTHORIZATION_SERVER],
    verify_token=verify_token,
    scopes_supported=["mcp"],
    required_scopes=["mcp"],
)
