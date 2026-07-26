# Hosted Miniflare disconnect investigation

Issue: [hayate-auth#28](https://github.com/hayatepy/hayate-auth/issues/28)

## Outcome

The intermittent `Error: Network connection lost` was not a D1 persistence
callback failure and workerd did not exit. It was a request-level disconnect in
Wrangler's development-only ProxyWorker-to-UserWorker hop, consistent with the
KJ five-second keep-alive race reported in
[cloudflare/workers-sdk#14641](https://github.com/cloudflare/workers-sdk/issues/14641).

The current-wheel acceptance profile now dispatches to the UserWorker
Miniflare created by Wrangler's exported `unstable_startWorker()` API. This
retains the real pinned workerd, Python Worker bundle, current hayate-auth
wheel, local D1 binding, persistence, and HTTP boundary while excluding the
unrelated outer development proxy. Production Cloudflare Workers requests do
not traverse that local Wrangler proxy.

Both artificial persistence yields were removed. The complete TOTP and OAuth
profile passed 20 of 20 independent hosted ARM64 jobs without a retry or
relaxed assertion.

## Pinned environment

- Node 24
- Wrangler 4.114.0
- Miniflare 4.20260722.0
- workerd 1.20260722.1
- Python 3.13 Worker
- local D1 with state outside the watched Worker source tree

These versions are locked by `spike/as-workers/package-lock.json` and the
hosted workflow.

## Evidence

| Experiment | Result | Interpretation |
| --- | --- | --- |
| Normal `wrangler dev` full profile | Intermittent non-JSON HTTP 500 at `POST /api/auth/two-factor/verify`; identical reruns passed | Request-level infrastructure race, not an auth assertion |
| Minimal Python Worker with only D1 write, five-second delay, and D1 read ([run 30212602292](https://github.com/hayatepy/hayate-auth/actions/runs/30212602292)) | 40/40 stock pairs and 40/40 pairs with the proposed Node loopback timeout patch passed | D1 persistence plus the delay is insufficient to reproduce |
| Full profile, stock versus the [workers-sdk#14850](https://github.com/cloudflare/workers-sdk/pull/14850) Node loopback patch ([run 30212751446](https://github.com/hayatepy/hayate-auth/actions/runs/30212751446)) | Stock 10/10; patched 8/10. Both patched failures were `Network connection lost` at the same TOTP request | The Miniflare workerd-to-Node loopback timeout is not this failure |
| Direct UserWorker Miniflare profile, no post-write yields ([run 30213371419](https://github.com/hayatepy/hayate-auth/actions/runs/30213371419)) | 20/20 complete profiles passed | The D1 callback is not the cause; excluding Wrangler's outer proxy is stable |

Earlier failure/pass pairs and exact request logs remain attached to issue 28.
The Wrangler process remained alive after failed requests and served the same
profile on rerun, so there was no useful workerd exit code to capture. The
useful failure reason is the request exception itself:

```text
Error: Network connection lost.
    at async Object.fetch (.../miniflare/dist/src/workers/core/entry.worker.js:4709:22)
```

The direct harness also subscribes to Wrangler `DevEnv` and workerd
`runtimeError` events. A future real runtime failure is therefore printed in
the job log instead of being reduced to a blank fatal message.

## Request paths

The flaky path was:

```text
test client
  -> Wrangler proxy Miniflare
  -> ProxyWorker
  -> KJ HTTP keep-alive hop
  -> UserWorker Miniflare
  -> Python Worker + D1
```

The acceptance path is now:

```text
test client
  -> small Node HTTP relay
  -> UserWorker Miniflare dispatchFetch()
  -> Python Worker + D1
```

The relay disables its own Node HTTP timeouts, forwards every status/header/body,
preserves multiple `Set-Cookie` headers, and uses manual redirect handling so
the Python acceptance client observes the Worker response exactly. It does not
retry requests.

## Reproduce

Run the minimal D1 probe:

```console
MINIFLARE_REPRO_ATTEMPTS=12 \
  bash scripts/reproduce_miniflare_d1_disconnect.sh
```

Run the complete current-wheel profile:

```console
bash scripts/check_current_workerd.sh
```

`scripts/serve_current_workerd_direct.mjs` is copied into the disposable Worker
directory by the complete check so Node resolves the exact locked Wrangler
installation. It fails closed if Wrangler stops exposing the local runtime.

## Upstream follow-up

- [workers-sdk#14641](https://github.com/cloudflare/workers-sdk/issues/14641)
  describes the matching ProxyWorker-to-UserWorker KJ keep-alive race and
  explains why fresh inbound client connections do not prevent it.
- [workers-sdk#14593](https://github.com/cloudflare/workers-sdk/pull/14593)
  corrects stale-worker error classification but does not repair the dropped
  request.
- [workers-sdk#14848](https://github.com/cloudflare/workers-sdk/issues/14848)
  and [#14850](https://github.com/cloudflare/workers-sdk/pull/14850) concern a
  different Node loopback server.

When #14641 ships in a pinned Wrangler release, re-run at least 20 hosted
profiles through normal `wrangler dev` before considering that outer proxy
stable. The direct profile should remain useful as the focused runtime/D1
acceptance layer even after that upgrade.
