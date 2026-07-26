# Miniflare Python Worker + D1 disconnect reproducer

This removes hayate, authentication, KDF, TOTP, and OAuth from the hosted
failure tracked in [hayate-auth issue 28](https://github.com/hayatepy/hayate-auth/issues/28).
The remaining Worker performs one D1 write, waits near the Node/workerd
five-second keep-alive boundary, and then performs one D1 read.

Run the stock pinned Wrangler/Miniflare:

```console
MINIFLARE_REPRO_ATTEMPTS=12 \
  bash scripts/reproduce_miniflare_d1_disconnect.sh
```

Each client request opens a fresh inbound connection. A
`Network connection lost` response therefore cannot be attributed to inbound
client keep-alive.
Set `MINIFLARE_REPRO_ALLOW_FAILURE=1` for a diagnostic job that should record
rather than fail.

On 2026-07-27, hosted `ubuntu-24.04-arm` run
[30212602292](https://github.com/hayatepy/hayate-auth/actions/runs/30212602292)
completed 40 stock and 40
[workers-sdk#14850](https://github.com/cloudflare/workers-sdk/pull/14850)-patched
write/read pairs without a disconnect. The full profile then failed twice with
that unrelated patch. The evidence rules out D1 plus a five-second delay and
the Miniflare Node loopback timeout as the cause of issue 28; the matching
upstream defect is the separate Wrangler dev-proxy race in
[workers-sdk#14641](https://github.com/cloudflare/workers-sdk/issues/14641).

See [the investigation](../../docs/research/miniflare-d1-disconnect.md) for the
complete evidence and the stable acceptance architecture.
