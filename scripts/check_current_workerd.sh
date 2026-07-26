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

npx --no-install wrangler dev \
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
    retry_dev_disconnect: bool = False,
) -> tuple[int, dict[str, Any], str | None]:
    # Production-cost scrypt is intentionally slow in Pyodide; this is a
    # correctness gate, not a latency benchmark.
    for attempt in range(2):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
        headers = {"content-type": "application/json"}
        if cookie is not None:
            headers["cookie"] = cookie
        connection.request("POST", path, json.dumps(data), headers)
        response = connection.getresponse()
        raw_body = response.read()
        set_cookie = response.getheader("set-cookie")
        status = response.status
        connection.close()

        if (
            retry_dev_disconnect
            and attempt == 0
            and status == 500
            and b"Network connection lost" in raw_body
        ):
            print(f"{path}: reconnecting after a Miniflare workerd disconnect")
            time.sleep(1)
            continue
        try:
            body = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"{path} returned HTTP {status} with non-JSON body {raw_body!r}"
            ) from exc
        return status, body, set_cookie
    raise AssertionError(f"{path} did not return after a dev-server reconnect")


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
status, _, _ = request(
    "/api/auth/two-factor/verify",
    {"code": code},
    cookie=session,
    retry_dev_disconnect=True,
)
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
