#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
worker_dir="${repo_dir}/spike/as-workers"
log_file="$(mktemp)"
response_dir="$(mktemp -d)"
# entry.py deliberately defaults the issuer to this local audit origin.
port=8787
server_pid=""

cleanup() {
  if [[ -n "${server_pid}" ]] && kill -0 "${server_pid}" 2>/dev/null; then
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

cd "${worker_dir}"
uv sync --locked
npm ci --ignore-scripts
uv run python -m hayate_auth generate --dialect d1 >"${response_dir}/schema.sql"
npx --no-install wrangler d1 execute AUTH_DB --local \
  --file "${response_dir}/schema.sql" >/dev/null
npx --no-install wrangler d1 execute AUTH_DB --local \
  --file "${response_dir}/schema.sql" >/dev/null

# Always ask pywrangler to reconcile the lock with the actual vendor tree.
# This repairs interrupted runs where a .synced marker exists without packages.
if [[ -f python_modules/.synced ]] && [[ ! -e python_modules/hayate_auth ]]; then
  mv python_modules/.synced "${response_dir}/stale-python-modules.synced"
fi
if [[ -f .venv-workers/.synced ]] && [[ ! -e .venv-workers/pyodide-venv ]]; then
  mv .venv-workers/.synced "${response_dir}/stale-venv-workers.synced"
fi
UV_PYTHON_DOWNLOADS=automatic UV_PYTHON_PREFERENCE=managed uv run pywrangler sync
test -e python_modules/hayate
test -e python_modules/hayate_auth
test -e python_modules/hayate_mcp

UV_PYTHON_DOWNLOADS=automatic UV_PYTHON_PREFERENCE=managed \
  uv run pywrangler dev --port "${port}" >"${log_file}" 2>&1 &
server_pid=$!

ready=false
for _ in {1..60}; do
  if curl --fail --silent --max-time 2 \
    "http://127.0.0.1:${port}/.well-known/oauth-authorization-server" \
    >"${response_dir}/authorization-server.json"; then
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

base_url="http://127.0.0.1:${port}"
curl --fail --silent --max-time 5 \
  "${base_url}/.well-known/oauth-protected-resource/mcp" \
  >"${response_dir}/protected-resource.json"
register_status="$(
  curl --silent --max-time 5 \
    --output "${response_dir}/client.json" \
    --write-out "%{http_code}" \
    --header "content-type: application/json" \
    --data '{"client_name":"audit-client","redirect_uris":["http://127.0.0.1/callback"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"]}' \
    "${base_url}/api/auth/oauth2/register"
)"
test "${register_status}" = "201"
test "$(
  curl --silent --max-time 5 --output /dev/null --write-out "%{http_code}" \
    "${base_url}/protected"
)" = "401"
test "$(
  curl --silent --max-time 5 --output /dev/null --write-out "%{http_code}" \
    --header "content-type: application/json" \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"audit","version":"1"}}}' \
    "${base_url}/mcp"
)" = "401"

python - "${response_dir}" "${base_url}" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
base = sys.argv[2]
authorization = json.loads((root / "authorization-server.json").read_text())
resource = json.loads((root / "protected-resource.json").read_text())
client = json.loads((root / "client.json").read_text())
assert authorization["issuer"] == base
assert authorization["code_challenge_methods_supported"] == ["S256"]
assert authorization["grant_types_supported"] == ["authorization_code", "refresh_token"]
assert resource["resource"] == f"{base}/mcp"
assert resource["authorization_servers"] == [base]
assert client["client_id"]
PY

echo "workerd/D1 audit profile passed"
