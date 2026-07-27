#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_worker="${repo_dir}/spike/as-workers"
dpop_worker_entry="${repo_dir}/spike/dpop-workers/entry.py"
test_dir="$(mktemp -d)"
log_file="${test_dir}.log"
dpop_only_log_file="${test_dir}.dpop-only.log"
# Keep the D1 persistence directory outside the watched Worker source tree;
# otherwise every SQLite write triggers a Wrangler source reload.
state_dir="$(mktemp -d)"
dpop_only_state_dir="$(mktemp -d)"
tooling_dir="$(mktemp -d)"
port=8792
dpop_only_port=8793
server_pid=""
dpop_only_server_pid=""

cleanup() {
  status=$?
  if [[ -n "${server_pid}" ]] && kill -0 "${server_pid}" 2>/dev/null; then
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
  if [[ -n "${dpop_only_server_pid}" ]] && kill -0 "${dpop_only_server_pid}" 2>/dev/null; then
    kill "${dpop_only_server_pid}" 2>/dev/null || true
    wait "${dpop_only_server_pid}" 2>/dev/null || true
  fi
  if [[ "${status}" -ne 0 ]] && [[ -f "${log_file}" ]]; then
    cat "${log_file}"
  fi
  if [[ "${status}" -ne 0 ]] && [[ -f "${dpop_only_log_file}" ]]; then
    cat "${dpop_only_log_file}"
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
cp "${dpop_worker_entry}" "${test_dir}/entry.py"
cp "${repo_dir}/scripts/serve_current_workerd_direct.mjs" "${test_dir}/"

cd "${test_dir}"
npm ci --ignore-scripts
"${repo_dir}/.venv/bin/python" -m hayate_auth generate --dialect d1 >schema.sql
npx --no-install wrangler d1 execute AUTH_DB --local \
  --persist-to "${state_dir}" --file schema.sql >/dev/null
npx --no-install wrangler d1 execute AUTH_DB --local \
  --persist-to "${dpop_only_state_dir}" --file schema.sql >/dev/null

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
node serve_current_workerd_direct.mjs \
  "${dpop_only_port}" \
  "${dpop_only_state_dir}" \
  true >"${dpop_only_log_file}" 2>&1 &
dpop_only_server_pid=$!

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

dpop_only_ready=false
for _ in {1..60}; do
  if curl --fail --silent --max-time 2 \
    "http://127.0.0.1:${dpop_only_port}/.well-known/oauth-authorization-server" >/dev/null; then
    dpop_only_ready=true
    break
  fi
  if ! kill -0 "${dpop_only_server_pid}" 2>/dev/null; then
    cat "${dpop_only_log_file}"
    exit 1
  fi
  sleep 1
done
if [[ "${dpop_only_ready}" != true ]]; then
  cat "${dpop_only_log_file}"
  exit 1
fi

"${repo_dir}/.venv/bin/python" - "${port}" "${dpop_only_port}" <<'PY'
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

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from hayate_auth import totp
from hayate_auth.dpop import access_token_hash, jwk_thumbprint

port = int(sys.argv[1])
dpop_only_port = int(sys.argv[2])


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


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def dpop_proof(
    private_key: Any,
    public_jwk: dict[str, str],
    *,
    jti: str,
    method: str,
    url: str,
    access_token: str | None = None,
) -> str:
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk}
    payload = {"jti": jti, "htm": method, "htu": url, "iat": int(time.time())}
    if access_token is not None:
        payload["ath"] = access_token_hash(access_token)
    encoded_header = b64url(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    signature = r.to_bytes(32) + s.to_bytes(32)
    return f"{encoded_header}.{encoded_payload}.{b64url(signature)}"


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

# RFC 9449 feasibility on the same workerd isolate. The token endpoint
# verifies ES256 through WebCrypto and records proof jti values atomically in
# D1; reusing a proof for a fresh authorization code is rejected.
private_key = ec.generate_private_key(ec.SECP256R1())
public_numbers = private_key.public_key().public_numbers()
public_jwk = {
    "kty": "EC",
    "crv": "P-256",
    "x": b64url(public_numbers.x.to_bytes(32)),
    "y": b64url(public_numbers.y.to_bytes(32)),
}
jkt = jwk_thumbprint(public_jwk)
dpop_resource = f"http://127.0.0.1:{port}/dpop-protected"
status, dpop_client, _ = request(
    "/api/auth/oauth2/register",
    {
        "client_name": "current-workerd-dpop-client",
        "redirect_uris": ["http://127.0.0.1/dpop-callback"],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "dpop_bound_access_tokens": True,
    },
)
assert status == 201
dpop_client_id = dpop_client["client_id"]
dpop_redirect_uri = dpop_client["redirect_uris"][0]
dpop_verifier = "workerd-dpop-verifier-with-sufficient-length-42"
dpop_challenge = b64url(hashlib.sha256(dpop_verifier.encode()).digest())
dpop_authorize_query = urlencode(
    {
        "response_type": "code",
        "client_id": dpop_client_id,
        "redirect_uri": dpop_redirect_uri,
        "state": "workerd-dpop",
        "code_challenge": dpop_challenge,
        "code_challenge_method": "S256",
        "scope": "mcp",
        "resource": dpop_resource,
        "dpop_jkt": jkt,
    }
)


def authorize_dpop() -> str:
    status, raw, headers = raw_request(
        "GET",
        f"/api/auth/oauth2/authorize?{dpop_authorize_query}",
        headers={"cookie": session},
    )
    assert status == 302, (status, raw, headers)
    location = next(value for name, value in headers if name.lower() == "location")
    if "/consent" not in location:
        return parse_qs(urlsplit(location).query)["code"][0]
    pending_header = next(
        value for name, value in headers if name.lower() == "set-cookie"
    )
    status, body, _ = request(
        "/api/auth/oauth2/consent",
        {"accept": True},
        cookie=f"{session}; {cookie_pair(pending_header)}",
    )
    assert status == 200
    return parse_qs(urlsplit(body["redirect_uri"]).query)["code"][0]


def exchange_dpop(value: str, proof: str) -> tuple[int, dict[str, Any]]:
    status, raw, _ = raw_request(
        "POST",
        "/api/auth/oauth2/token",
        urlencode(
            {
                "grant_type": "authorization_code",
                "code": value,
                "code_verifier": dpop_verifier,
                "redirect_uri": dpop_redirect_uri,
                "client_id": dpop_client_id,
                "resource": dpop_resource,
            }
        ),
        {
            "content-type": "application/x-www-form-urlencoded",
            "dpop": proof,
        },
    )
    return status, json.loads(raw)


token_url = f"http://127.0.0.1:{port}/api/auth/oauth2/token"
shared_proof = dpop_proof(
    private_key,
    public_jwk,
    jti="workerd-shared-proof",
    method="POST",
    url=token_url,
)
status, dpop_tokens = exchange_dpop(authorize_dpop(), shared_proof)
assert status == 200, dpop_tokens
assert dpop_tokens["token_type"] == "DPoP"
resource_proof = dpop_proof(
    private_key,
    public_jwk,
    jti="workerd-resource-proof",
    method="GET",
    url=dpop_resource,
    access_token=dpop_tokens["access_token"],
)
status, _, _ = raw_request(
    "GET",
    "/dpop-protected",
    headers={
        "authorization": f"DPoP {dpop_tokens['access_token']}",
        "dpop": resource_proof,
    },
)
assert status == 200
status, _, _ = raw_request(
    "GET",
    "/dpop-protected",
    headers={
        "authorization": f"DPoP {dpop_tokens['access_token']}",
        "dpop": resource_proof,
    },
)
assert status == 401
second_dpop_code = authorize_dpop()
status, replay_error = exchange_dpop(second_dpop_code, shared_proof)
assert status == 400
assert replay_error["error"] == "invalid_dpop_proof"
status, dpop_tokens = exchange_dpop(
    second_dpop_code,
    dpop_proof(
        private_key,
        public_jwk,
        jti="workerd-fresh-proof",
        method="POST",
        url=token_url,
    ),
)
assert status == 200, dpop_tokens

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
matching_consents = [item for item in consents if item["client_id"] == client_id]
assert len(matching_consents) == 1
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

# A second real workerd isolate enables the authorization-server-wide policy.
# The client deliberately does not opt in through registration: global policy
# must still make dpop_jkt and token/refresh proofs mandatory.
port = dpop_only_port
status, _, header = request(
    "/api/auth/sign-up/email",
    {"email": "workerd-dpop-only@example.com", "password": "long enough"},
)
assert status == 200
dpop_only_session = cookie_pair(header)
status, dpop_only_client, _ = request(
    "/api/auth/oauth2/register",
    {
        "client_name": "server-wide-dpop-client",
        "redirect_uris": ["http://127.0.0.1/dpop-only-callback"],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    },
)
assert status == 201
assert dpop_only_client["dpop_bound_access_tokens"] is False
dpop_only_client_id = dpop_only_client["client_id"]
dpop_only_redirect_uri = dpop_only_client["redirect_uris"][0]
dpop_only_resource = f"http://127.0.0.1:{port}/dpop-protected"
dpop_only_verifier = "workerd-server-wide-dpop-verifier-sufficient-42"
dpop_only_challenge = b64url(hashlib.sha256(dpop_only_verifier.encode()).digest())
dpop_only_params = {
    "response_type": "code",
    "client_id": dpop_only_client_id,
    "redirect_uri": dpop_only_redirect_uri,
    "state": "server-wide-dpop",
    "code_challenge": dpop_only_challenge,
    "code_challenge_method": "S256",
    "scope": "mcp",
    "resource": dpop_only_resource,
}
status, _, headers = raw_request(
    "GET",
    f"/api/auth/oauth2/authorize?{urlencode(dpop_only_params)}",
    headers={"cookie": dpop_only_session},
)
assert status == 302
location = next(value for name, value in headers if name.lower() == "location")
missing_jkt_error = parse_qs(urlsplit(location).query)
assert missing_jkt_error["error"] == ["invalid_request"]
assert "code" not in missing_jkt_error

dpop_only_params["dpop_jkt"] = jkt
status, _, headers = raw_request(
    "GET",
    f"/api/auth/oauth2/authorize?{urlencode(dpop_only_params)}",
    headers={"cookie": dpop_only_session},
)
assert status == 302
pending_header = next(
    value for name, value in headers if name.lower() == "set-cookie"
)
status, body, _ = request(
    "/api/auth/oauth2/consent",
    {"accept": True},
    cookie=f"{dpop_only_session}; {cookie_pair(pending_header)}",
)
assert status == 200
dpop_only_code = parse_qs(urlsplit(body["redirect_uri"]).query)["code"][0]
dpop_only_token_url = f"http://127.0.0.1:{port}/api/auth/oauth2/token"
dpop_only_code_form = {
    "grant_type": "authorization_code",
    "code": dpop_only_code,
    "code_verifier": dpop_only_verifier,
    "redirect_uri": dpop_only_redirect_uri,
    "client_id": dpop_only_client_id,
    "resource": dpop_only_resource,
}
status, raw, _ = raw_request(
    "POST",
    "/api/auth/oauth2/token",
    urlencode(dpop_only_code_form),
    {"content-type": "application/x-www-form-urlencoded"},
)
assert status == 400
assert json.loads(raw)["error"] == "invalid_dpop_proof"
status, raw, _ = raw_request(
    "POST",
    "/api/auth/oauth2/token",
    urlencode(dpop_only_code_form),
    {
        "content-type": "application/x-www-form-urlencoded",
        "dpop": dpop_proof(
            private_key,
            public_jwk,
            jti="workerd-server-wide-code-proof",
            method="POST",
            url=dpop_only_token_url,
        ),
    },
)
assert status == 200
dpop_only_tokens = json.loads(raw)
assert dpop_only_tokens["token_type"] == "DPoP"
status, _, _ = raw_request(
    "GET",
    "/dpop-protected",
    headers={
        "authorization": f"DPoP {dpop_only_tokens['access_token']}",
        "dpop": dpop_proof(
            private_key,
            public_jwk,
            jti="workerd-server-wide-resource-proof",
            method="GET",
            url=dpop_only_resource,
            access_token=dpop_only_tokens["access_token"],
        ),
    },
)
assert status == 200

dpop_only_refresh_form = {
    "grant_type": "refresh_token",
    "refresh_token": dpop_only_tokens["refresh_token"],
    "client_id": dpop_only_client_id,
    "resource": dpop_only_resource,
}
status, raw, _ = raw_request(
    "POST",
    "/api/auth/oauth2/token",
    urlencode(dpop_only_refresh_form),
    {"content-type": "application/x-www-form-urlencoded"},
)
assert status == 400
assert json.loads(raw)["error"] == "invalid_dpop_proof"
status, raw, _ = raw_request(
    "POST",
    "/api/auth/oauth2/token",
    urlencode(dpop_only_refresh_form),
    {
        "content-type": "application/x-www-form-urlencoded",
        "dpop": dpop_proof(
            private_key,
            public_jwk,
            jti="workerd-server-wide-refresh-proof",
            method="POST",
            url=dpop_only_token_url,
        ),
    },
)
assert status == 200
assert json.loads(raw)["token_type"] == "DPoP"
PY

echo "current wheel workerd/D1 TOTP, OAuth revocation, and mixed/DPoP-only profiles passed"
