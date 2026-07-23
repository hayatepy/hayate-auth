"""The complete OAuth loop with the official MCP SDK client, over real HTTP.

The SDK's OAuthClientProvider does exactly what MCP Inspector and Claude
Code do: hit /mcp unauthenticated, follow the 401 to the protected-resource
metadata, discover the AS (RFC 8414), self-register (RFC 7591), and run
authorization-code + PKCE. The browser hops (login, consent) are automated
with an httpx session standing in for the user.
"""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from mcp import ClientSession
from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken
from pydantic import AnyUrl

ROOT = Path(__file__).resolve().parent.parent
PORT = 8931
BASE = f"http://127.0.0.1:{PORT}"


@pytest.fixture(scope="module")
def endpoint():
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app:app", "--port", str(PORT)],
        cwd=ROOT,
        env={**os.environ, "AUTH_DB": ":memory:"},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", PORT), timeout=1):
                    break
            except OSError:
                if proc.poll() is not None:
                    raise RuntimeError("uvicorn exited early") from None
                time.sleep(0.2)
        else:
            raise RuntimeError("uvicorn did not start listening")
        yield f"{BASE}/mcp"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


class MemoryTokenStorage(TokenStorage):
    def __init__(self) -> None:
        self.tokens: OAuthToken | None = None
        self.client_info: OAuthClientInformationFull | None = None

    async def get_tokens(self) -> OAuthToken | None:
        return self.tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self.tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self.client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self.client_info = client_info


async def test_unauthenticated_request_points_at_the_metadata(endpoint):
    async with httpx.AsyncClient() as anon:
        res = await anon.post(
            endpoint,
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={"accept": "application/json, text/event-stream"},
        )
        assert res.status_code == 401
        challenge = res.headers.get("www-authenticate", "")
        assert "resource_metadata=" in challenge

        # RFC 9728 §3.1 path-insertion: the well-known segment goes between
        # host and the resource's path (hayate-mcp >= 0.6.0).
        prm_url = f"{BASE}/.well-known/oauth-protected-resource/mcp"
        assert challenge.partition('resource_metadata="')[2].startswith(prm_url)
        prm = await anon.get(prm_url)
        assert prm.status_code == 200
        doc = prm.json()
        assert doc["resource"] == endpoint
        assert doc["authorization_servers"] == [BASE]

        asm = await anon.get(f"{BASE}/.well-known/oauth-authorization-server")
        assert asm.status_code == 200
        assert asm.json()["issuer"] == BASE


async def test_official_client_full_oauth_round_trip(endpoint):
    async with httpx.AsyncClient(base_url=BASE) as browser:
        # The human signs up once; the httpx cookie jar now carries the
        # session the same way a browser would.
        signup = await browser.post(
            "/api/auth/sign-up/email",
            json={"email": "demo@example.com", "password": "demo password 42"},
        )
        assert signup.status_code == 200

        captured: dict[str, str] = {}

        async def redirect_handler(authorization_url: str) -> None:
            # What a browser would do: follow the authorize URL (signed in),
            # land on /consent, approve, and note the final redirect.
            hop = await browser.get(str(authorization_url), follow_redirects=False)
            assert hop.status_code == 302
            assert "/consent?" in hop.headers["location"]
            decision = await browser.post("/api/auth/oauth2/consent", json={"accept": True})
            assert decision.status_code == 200
            captured["redirect"] = decision.json()["redirect_uri"]

        async def callback_handler() -> tuple[str, str | None]:
            query = parse_qs(urlsplit(captured["redirect"]).query)
            return query["code"][0], query.get("state", [None])[0]

        oauth = OAuthClientProvider(
            server_url=endpoint,
            client_metadata=OAuthClientMetadata(
                client_name="e2e sdk client",
                redirect_uris=[AnyUrl("http://localhost:23456/callback")],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                token_endpoint_auth_method="none",
                scope="mcp",
            ),
            storage=MemoryTokenStorage(),
            redirect_handler=redirect_handler,
            callback_handler=callback_handler,
        )

        async with (
            create_mcp_http_client(auth=oauth) as http_client,
            streamable_http_client(endpoint, http_client=http_client) as (
                read,
                write,
                _get_session_id,
            ),
            ClientSession(read, write) as session,
        ):
            result = await session.initialize()
            assert result.serverInfo.name == "hayate-oauth-demo"

            tools = await session.list_tools()
            assert [tool.name for tool in tools.tools] == ["echo"]

            outcome = await session.call_tool("echo", {"text": "with oauth"})
            assert outcome.content[0].text == "echo: with oauth"
