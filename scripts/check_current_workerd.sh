#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_worker="${repo_dir}/spike/as-workers"
test_dir="$(mktemp -d)"
log_file="${test_dir}.log"
# Keep the D1 persistence directory outside the watched Worker source tree;
# otherwise every SQLite write triggers a Wrangler source reload.
state_dir="$(mktemp -d)"
tooling_dir="$(mktemp -d)"
port=8792
server_pid=""

cleanup() {
  status=$?
  if [[ -n "${server_pid}" ]] && kill -0 "${server_pid}" 2>/dev/null; then
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
  if [[ "${status}" -ne 0 ]] && [[ -f "${log_file}" ]]; then
    cat "${log_file}"
  fi
  exit "${status}"
}
trap cleanup EXIT

mkdir -p "${test_dir}/dist"
uv build --wheel --out-dir "${test_dir}/dist"
wheel_path="$(find "${test_dir}/dist" -name 'hayate_auth-*.whl' -print -quit)"
test -n "${wheel_path}"

for file in entry.py package-lock.json package.json pylock.toml pyproject.toml wrangler.toml; do
  cp "${source_worker}/${file}" "${test_dir}/${file}"
done
cp "${repo_dir}/scripts/serve_current_workerd_direct.mjs" "${test_dir}/"

cd "${test_dir}"
npm ci --ignore-scripts
"${repo_dir}/.venv/bin/python" -m hayate_auth generate --dialect d1 >schema.sql
npx --no-install wrangler d1 execute AUTH_DB --local \
  --persist-to "${state_dir}" --file schema.sql >/dev/null

# Install the locked wasm wheels directly into the only directory Wrangler
# should bundle. Pywrangler also creates host tooling virtualenvs beside the
# Worker, which Wrangler recursively discovers and would ship.
uv pip install \
  --python "${repo_dir}/.venv" \
  --python-platform wasm32-pyodide2025 \
  --python-version 3.13 \
  --target python_modules \
  --no-build \
  --preview-features pylock \
  -r pylock.toml
uv pip install \
  --target "${tooling_dir}/current-wheel" \
  --no-deps \
  "${wheel_path}"
mv python_modules/hayate_auth "${tooling_dir}/released-hayate-auth"
mv "${tooling_dir}/current-wheel/hayate_auth" python_modules/hayate_auth
test -e python_modules/hayate
test -e python_modules/hayate_auth
test -e python_modules/hayate_fetch
test -e python_modules/hayate_mcp

node serve_current_workerd_direct.mjs \
  "${port}" \
  "${state_dir}" >"${log_file}" 2>&1 &
server_pid=$!

ready=false
for _ in {1..60}; do
  if curl --fail --silent --max-time 2 \
    "http://127.0.0.1:${port}/.well-known/oauth-authorization-server" >/dev/null; then
    ready=true
    break
  fi
  if ! kill -0 "${server_pid}" 2>/dev/null; then
    cat "${log_file}"
    exit 1
  fi
  sleep 1
done
if [[ "${ready}" != true ]]; then
  cat "${log_file}"
  exit 1
fi

"${repo_dir}/.venv/bin/python" - "${port}" <<'PY'
from __future__ import annotations

import http.client
import base64
import hashlib
import json
import sys
import time
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from hayate_auth import totp

port = int(sys.argv[1])


def raw_request(
    method: str,
    path: str,
    body: str | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes, list[tuple[str, str]]]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
    connection.request(method, path, body, headers or {})
    response = connection.getresponse()
    status = response.status
    raw_body = response.read()
    response_headers = response.getheaders()
    connection.close()
    return status, raw_body, response_headers


def request(
    path: str,
    data: dict[str, Any],
    *,
    cookie: str | None = None,
) -> tuple[int, dict[str, Any], str | None]:
    headers = {"content-type": "application/json"}
    if cookie is not None:
        headers["cookie"] = cookie
    status, raw_body, response_headers = raw_request(
        "POST", path, json.dumps(data), headers
    )
    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"{path} returned HTTP {status} with non-JSON body {raw_body!r}"
        ) from exc
    set_cookie = next(
        (value for name, value in response_headers if name.lower() == "set-cookie"),
        None,
    )
    return status, body, set_cookie


def cookie_pair(header: str | None) -> str:
    assert header is not None
    parsed = SimpleCookie()
    parsed.load(header)
    key = next(iter(parsed))
    return f"{key}={parsed[key].value}"


status, body, _ = request(
    "/api/auth/sign-up/email",
    {"email": "blocked@example.com", "password": "password"},
)
assert status == 400
assert body["title"] == "Password is commonly used or has been compromised"

status, _, header = request(
    "/api/auth/sign-up/email",
    {"email": "workerd-totp@example.com", "password": "long enough"},
)
assert status == 200
session = cookie_pair(header)

status, enrollment, _ = request("/api/auth/two-factor/enable", {}, cookie=session)
assert status == 200
status, _, _ = request(
    "/api/auth/two-factor/verify", {"code": "not-a-code"}, cookie=session
)
assert status == 400
code = totp.code_at(enrollment["secret"], time.time())
status, _, _ = request("/api/auth/two-factor/verify", {"code": code}, cookie=session)
assert status == 200

status, _, header = request(
    "/api/auth/sign-in/email",
    {"email": "workerd-totp@example.com", "password": "long enough"},
)
assert status == 200
challenge = cookie_pair(header)
first, _, _ = request("/api/auth/sign-in/two-factor", {"code": code}, cookie=challenge)
replay, _, _ = request("/api/auth/sign-in/two-factor", {"code": code}, cookie=challenge)
assert (first, replay) == (200, 401)

# Current-wheel OAuth management acceptance on the same real workerd + D1
# runtime: public-client revocation, consent listing/revocation, and immediate
# bearer rejection.
status, client_body, _ = request(
    "/api/auth/oauth2/register",
    {
        "client_name": "current-workerd-client",
        "redirect_uris": ["http://127.0.0.1/callback"],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    },
)
assert status == 201
client_id = client_body["client_id"]
redirect_uri = client_body["redirect_uris"][0]
resource = f"http://127.0.0.1:{port}/protected"
verifier = "workerd-oauth-verifier-with-sufficient-length-42"
challenge = (
    base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    .decode()
    .rstrip("=")
)
authorize_query = urlencode(
    {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": "workerd",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "scope": "mcp",
        "resource": resource,
    }
)
status, raw, headers = raw_request(
    "GET",
    f"/api/auth/oauth2/authorize?{authorize_query}",
    headers={"cookie": session},
)
assert status == 302, (status, raw, headers)
pending_header = next(
    value for name, value in headers if name.lower() == "set-cookie"
)
pending = cookie_pair(pending_header)
status, consent_body, _ = request(
    "/api/auth/oauth2/consent",
    {"accept": True},
    cookie=f"{session}; {pending}",
)
assert status == 200
code = parse_qs(urlsplit(consent_body["redirect_uri"]).query)["code"][0]


def exchange_code(value: str) -> dict[str, Any]:
    status, raw, _ = raw_request(
        "POST",
        "/api/auth/oauth2/token",
        urlencode(
            {
                "grant_type": "authorization_code",
                "code": value,
                "code_verifier": verifier,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "resource": resource,
            }
        ),
        {"content-type": "application/x-www-form-urlencoded"},
    )
    body = json.loads(raw)
    assert status == 200, body
    return body


tokens = exchange_code(code)
status, _, _ = raw_request(
    "GET",
    "/protected",
    headers={"authorization": f"Bearer {tokens['access_token']}"},
)
assert status == 200
status, raw, _ = raw_request(
    "POST",
    "/api/auth/oauth2/revoke",
    urlencode({"token": tokens["access_token"], "client_id": client_id}),
    {"content-type": "application/x-www-form-urlencoded"},
)
assert status == 200
assert raw == b""
status, _, _ = raw_request(
    "GET",
    "/protected",
    headers={"authorization": f"Bearer {tokens['access_token']}"},
)
assert status == 401

# Existing consent remains after a client revokes one token family. Mint a
# second family without another consent hop, then revoke the user's grant.
status, _, headers = raw_request(
    "GET",
    f"/api/auth/oauth2/authorize?{authorize_query}",
    headers={"cookie": session},
)
assert status == 302
location = next(value for name, value in headers if name.lower() == "location")
code = parse_qs(urlsplit(location).query)["code"][0]
second = exchange_code(code)
status, raw, _ = raw_request(
    "GET",
    "/api/auth/oauth2/consents",
    headers={"cookie": session},
)
assert status == 200
consents = json.loads(raw)["consents"]
assert len(consents) == 1
assert consents[0]["client_id"] == client_id
status, body, _ = request(
    "/api/auth/oauth2/consents/revoke",
    {"client_id": client_id},
    cookie=session,
)
assert status == 200
assert body == {"success": True}
status, _, _ = raw_request(
    "GET",
    "/protected",
    headers={"authorization": f"Bearer {second['access_token']}"},
)
assert status == 401
PY

echo "current wheel workerd/D1 TOTP and OAuth revocation profile passed"
