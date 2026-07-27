#!/usr/bin/env node

import http from "node:http";
import { once } from "node:events";
import process from "node:process";
import { unstable_startWorker } from "wrangler";

const [portArgument, stateDirectory, requireDpop = "false"] =
  process.argv.slice(2);
const port = Number(portArgument);
if (
  !Number.isInteger(port) ||
  port < 1 ||
  port > 65535 ||
  !stateDirectory ||
  !["false", "true"].includes(requireDpop)
) {
  throw new Error(
    "usage: serve_current_workerd_direct.mjs <port> <persistence-directory> [true|false]",
  );
}

let worker;
let server;
let stopping = false;

async function stop(exitCode = 0) {
  if (stopping) return;
  stopping = true;
  if (server !== undefined) {
    await new Promise((resolve) => server.close(resolve));
  }
  await worker?.dispose();
  process.exitCode = exitCode;
}

process.on("SIGINT", () => void stop());
process.on("SIGTERM", () => void stop());
process.on("uncaughtException", (error) => {
  console.error(error);
  void stop(1);
});
process.on("unhandledRejection", (error) => {
  console.error(error);
  void stop(1);
});

worker = await unstable_startWorker({
  config: "wrangler.toml",
  bindings: {
    ISSUER: {
      type: "plain_text",
      value: `http://127.0.0.1:${port}`,
    },
    REQUIRE_DPOP: {
      type: "plain_text",
      value: requireDpop,
    },
  },
  dev: {
    remote: false,
    persist: stateDirectory,
    watch: false,
    inspector: false,
    server: { hostname: "127.0.0.1", port: 0 },
    logLevel: "info",
  },
});
worker.raw.on("error", (event) => {
  console.error("Wrangler DevEnv error", event);
});
worker.raw.on("runtimeError", (event) => {
  console.error("workerd runtime error", event);
});
const reloadComplete = once(worker.raw, "reloadComplete");
await worker.ready;
const [reloadEvent] = await reloadComplete;

// Wrangler's public fetch path traverses a separate ProxyWorker. workerd issue
// cloudflare/workers-sdk#14641 can drop non-idempotent requests at the KJ
// five-second keep-alive boundary in that development-only hop. Dispatch
// directly to the already-built UserWorker so this acceptance check still runs
// the real current workerd, Python Worker, and D1 binding without testing the
// unrelated outer proxy. `dispatchFetch()` targets this UserWorker Miniflare,
// not Wrangler's separate development proxy Miniflare.
const runtime = worker.raw.runtimes.find((candidate) => candidate.mf !== undefined);
if (runtime?.mf === undefined) {
  throw new Error("Wrangler did not expose the local Miniflare runtime");
}

server = http.createServer(async (incoming, outgoing) => {
  try {
    const chunks = [];
    for await (const chunk of incoming) chunks.push(chunk);
    const body = chunks.length === 0 ? undefined : Buffer.concat(chunks);
    const url = `http://127.0.0.1:${port}${incoming.url ?? "/"}`;
    const response = await runtime.mf.dispatchFetch(
      url,
      {
        method: incoming.method,
        headers: {
          ...incoming.headers,
          ...reloadEvent.proxyData.headers,
          "MF-Original-URL": url,
        },
        body,
        redirect: "manual",
      },
    );
    outgoing.statusCode = response.status;
    for (const [name, value] of response.headers) {
      if (name !== "set-cookie") outgoing.setHeader(name, value);
    }
    const setCookies = response.headers.getSetCookie();
    if (setCookies.length !== 0) outgoing.setHeader("set-cookie", setCookies);
    outgoing.end(Buffer.from(await response.arrayBuffer()));
  } catch (error) {
    console.error("direct UserWorker dispatch failed", error);
    if (!outgoing.headersSent) {
      outgoing.statusCode = 500;
      outgoing.setHeader("content-type", "text/plain; charset=utf-8");
    }
    outgoing.end(error instanceof Error ? error.stack : String(error));
  }
});
server.keepAliveTimeout = 0;
server.headersTimeout = 0;
await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(port, "127.0.0.1", resolve);
});
console.log(`direct current UserWorker ready on http://127.0.0.1:${port}`);
