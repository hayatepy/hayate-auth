#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_worker="${repo_dir}/spike/as-workers"
test_dir="$(mktemp -d)"
log_file="${test_dir}.log"
# Keep the D1 persistence directory outside the watched Worker source tree;
# otherwise every SQLite write triggers a Wrangler source reload.
state_dir="$(mktemp -d)"
port=8792
server_pid=""

cleanup() {
  if [[ -n "${server_pid}" ]] && kill -0 "${server_pid}" 2>/dev/null; then
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

mkdir -p "${test_dir}/dist"
uv build --wheel --out-dir "${test_dir}/dist"
wheel_path="$(find "${test_dir}/dist" -name 'hayate_auth-*.whl' -print -quit)"
test -n "${wheel_path}"

for file in entry.py package-lock.json package.json pylock.toml pyproject.toml wrangler.toml; do
  cp "${source_worker}/${file}" "${test_dir}/${file}"
done

cd "${test_dir}"
npm ci --ignore-scripts
"${repo_dir}/.venv/bin/python" -m hayate_auth generate --dialect d1 >schema.sql
npx --no-install wrangler d1 execute AUTH_DB --local \
  --persist-to "${state_dir}" --file schema.sql >/dev/null

uvx --from workers-py==1.15.0 pywrangler sync
uv pip install \
  --target python_modules \
  --reinstall \
  --no-deps \
  "${wheel_path}"
test -e python_modules/hayate_auth

uvx --from workers-py==1.15.0 pywrangler dev \
  --port "${port}" --persist-to "${state_dir}" >"${log_file}" 2>&1 &
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
import json
import sys
import time
from http.cookies import SimpleCookie
from typing import Any

from hayate_auth import totp

port = int(sys.argv[1])


def request(
    path: str,
    data: dict[str, Any],
    *,
    cookie: str | None = None,
) -> tuple[int, dict[str, Any], str | None]:
    # Production-cost scrypt is intentionally slow in Pyodide; this is a
    # correctness gate, not a latency benchmark.
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
    headers = {"content-type": "application/json"}
    if cookie is not None:
        headers["cookie"] = cookie
    connection.request("POST", path, json.dumps(data), headers)
    response = connection.getresponse()
    body = json.loads(response.read())
    set_cookie = response.getheader("set-cookie")
    connection.close()
    return response.status, body, set_cookie


def cookie_pair(header: str | None) -> str:
    assert header is not None
    parsed = SimpleCookie()
    parsed.load(header)
    key = next(iter(parsed))
    return f"{key}={parsed[key].value}"


status, _, header = request(
    "/api/auth/sign-up/email",
    {"email": "workerd-totp@example.com", "password": "long enough"},
)
assert status == 200
session = cookie_pair(header)

status, enrollment, _ = request("/api/auth/two-factor/enable", {}, cookie=session)
assert status == 200
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
PY

echo "current wheel workerd/D1 TOTP replay profile passed"
