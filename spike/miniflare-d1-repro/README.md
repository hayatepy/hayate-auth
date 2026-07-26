# Miniflare Python Worker + D1 disconnect reproducer

This removes hayate, authentication, KDF, TOTP, and OAuth from the hosted
failure tracked in hayate-auth issue 28. The remaining Worker performs one D1
write, waits near the Node/workerd five-second keep-alive boundary, and then
performs one D1 read.

Run the stock pinned Wrangler/Miniflare:

```console
MINIFLARE_REPRO_ATTEMPTS=12 \
  bash scripts/reproduce_miniflare_d1_disconnect.sh
```

Run the same workload with only the proposed
[workers-sdk#14850](https://github.com/cloudflare/workers-sdk/pull/14850)
loopback timeout fix backported:

```console
MINIFLARE_LOOPBACK_PATCH=1 MINIFLARE_REPRO_ATTEMPTS=12 \
  bash scripts/reproduce_miniflare_d1_disconnect.sh
```

Each client request opens a fresh inbound connection. A
`Network connection lost` response therefore comes from the internal
workerd-to-Node loopback used by the D1 binding, not from client keep-alive.
Set `MINIFLARE_REPRO_ALLOW_FAILURE=1` for an A/B diagnostic job that should
record rather than fail on the stock variant.

On 2026-07-27, the hosted `ubuntu-24.04-arm` probe completed 40 stock and 40
patched write/read pairs without a disconnect. This minimal workload therefore
rules out D1 plus a five-second delay alone, but does not reproduce the
intermittent full hayate-auth profile tracked in issue 28.
