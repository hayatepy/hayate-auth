#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="${repo_dir}/spike/miniflare-d1-repro"
work_dir="$(mktemp -d)"
state_dir="$(mktemp -d)"
tooling_dir="$(mktemp -d)"
server_log="${work_dir}.wrangler.log"
debug_log="${work_dir}.debug.log"
server_pid=""
port=8793

cleanup() {
  status=$?
  if [[ -n "${server_pid}" ]] && kill -0 "${server_pid}" 2>/dev/null; then
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
  if [[ "${status}" -ne 0 ]]; then
    test ! -f "${server_log}" || tail -n 200 "${server_log}"
    test ! -f "${debug_log}" || tail -n 200 "${debug_log}"
  fi
  exit "${status}"
}
trap cleanup EXIT

cp "${source_dir}/entry.py" "${work_dir}/entry.py"
cp "${source_dir}/schema.sql" "${work_dir}/schema.sql"
cp "${source_dir}/wrangler.toml" "${work_dir}/wrangler.toml"
cp "${repo_dir}/spike/as-workers/package.json" "${tooling_dir}/package.json"
cp "${repo_dir}/spike/as-workers/package-lock.json" "${tooling_dir}/package-lock.json"

cd "${tooling_dir}"
npm ci --ignore-scripts >/dev/null
if [[ "${MINIFLARE_LOOPBACK_PATCH:-0}" == "1" ]]; then
  node "${repo_dir}/scripts/patch_miniflare_loopback.cjs" \
    "${tooling_dir}/node_modules/miniflare/dist/src/index.js"
fi

wrangler="${tooling_dir}/node_modules/.bin/wrangler"
cd "${work_dir}"
"${wrangler}" d1 execute REPRO_DB --local \
  --persist-to "${state_dir}" --file schema.sql >/dev/null
WRANGLER_LOG=debug WRANGLER_LOG_PATH="${debug_log}" \
  "${wrangler}" dev --port "${port}" --persist-to "${state_dir}" \
  >"${server_log}" 2>&1 &
server_pid=$!

ready=false
for _ in {1..60}; do
  if curl --fail --silent --max-time 2 \
    "http://127.0.0.1:${port}/health" >/dev/null; then
    ready=true
    break
  fi
  if ! kill -0 "${server_pid}" 2>/dev/null; then
    exit 1
  fi
  sleep 1
done
if [[ "${ready}" != true ]]; then
  exit 1
fi

"${repo_dir}/.venv/bin/python" - \
  "${port}" \
  "${MINIFLARE_REPRO_ATTEMPTS:-12}" \
  "${MINIFLARE_REPRO_DELAY_SECONDS:-5}" \
  "${MINIFLARE_REPRO_ALLOW_FAILURE:-0}" <<'PY'
from __future__ import annotations

import http.client
import json
import sys
import time

port = int(sys.argv[1])
attempts = int(sys.argv[2])
delay = float(sys.argv[3])
allow_failure = sys.argv[4] == "1"
disconnects: list[dict[str, object]] = []


def request(method: str, path: str) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    connection.request(method, path)
    response = connection.getresponse()
    status = response.status
    body = response.read()
    connection.close()
    return status, body


for attempt in range(1, attempts + 1):
    for phase, method, path in (
        ("write", "POST", "/write"),
        ("read", "GET", "/read"),
    ):
        if phase == "read":
            time.sleep(delay)
        status, body = request(method, path)
        if status >= 500 or b"Network connection lost" in body:
            disconnects.append(
                {
                    "attempt": attempt,
                    "phase": phase,
                    "status": status,
                    "body": body.decode(errors="replace")[:500],
                }
            )

summary = {
    "attempts": attempts,
    "delay_seconds": delay,
    "disconnect_count": len(disconnects),
    "disconnects": disconnects,
}
print(json.dumps(summary, sort_keys=True))
if disconnects and not allow_failure:
    raise SystemExit(1)
PY
