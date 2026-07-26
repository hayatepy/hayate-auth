#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");

const requested = process.argv[2];
if (!requested) {
  throw new Error("usage: patch_miniflare_loopback.cjs <miniflare dist/src/index.js>");
}

const target = path.resolve(requested);
const expectedSuffix = path.join("node_modules", "miniflare", "dist", "src", "index.js");
if (!target.endsWith(expectedSuffix)) {
  throw new Error(`refusing unexpected Miniflare target: ${target}`);
}

const marker = "server.keepAliveTimeout = 0;";
const anchor = '      server.on("upgrade", this.#handleLoopbackUpgrade);';
const replacement = [
  "      // Temporary backport of cloudflare/workers-sdk#14850.",
  "      server.keepAliveTimeout = 0;",
  "      server.headersTimeout = 0;",
  anchor,
].join("\n");

const source = fs.readFileSync(target, "utf8");
if (source.includes(marker)) {
  process.stdout.write("Miniflare loopback timeouts are already disabled\n");
  process.exit(0);
}
const occurrences = source.split(anchor).length - 1;
if (occurrences !== 1) {
  throw new Error(`expected one Miniflare loopback anchor, found ${occurrences}`);
}

fs.writeFileSync(target, source.replace(anchor, replacement));
process.stdout.write("disabled Miniflare loopback keep-alive/header timeouts\n");
