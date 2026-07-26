#!/usr/bin/env python3
"""Reproducible SQLite baseline for the RFC 9449 replay store.

This measures the storage/write cost of the same AdapterDPoPReplayStore used
by ASGI and D1 deployments.  D1 network latency is environment-specific; the
operation count stays one INSERT per accepted proof, plus one amortized
expiry DELETE per cleanup interval.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import tempfile
import time
from datetime import UTC, datetime, timedelta

from hayate_auth import AdapterDPoPReplayStore
from hayate_auth.adapters.sqlite import SQLiteAdapter


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


async def benchmark(samples: int) -> dict[str, object]:
    descriptor, path = tempfile.mkstemp(prefix="hayate-dpop-", suffix=".sqlite3")
    os.close(descriptor)
    adapter = SQLiteAdapter(path)
    try:
        adapter.create_tables()
        baseline_size = os.path.getsize(path)
        store = AdapterDPoPReplayStore(adapter, cleanup_interval=timedelta(hours=1))
        expiry = datetime.now(UTC) + timedelta(minutes=6)
        latencies: list[float] = []
        start = time.perf_counter()
        for index in range(samples):
            before = time.perf_counter()
            accepted = await store.record(
                jkt="A" * 43,
                jti=f"benchmark-proof-{index:016x}",
                expires_at=expiry,
            )
            if not accepted:
                raise RuntimeError("fresh benchmark proof was classified as a replay")
            latencies.append((time.perf_counter() - before) * 1000)
        elapsed = time.perf_counter() - start
        final_size = os.path.getsize(path)

        before = time.perf_counter()
        replay_accepted = await store.record(
            jkt="A" * 43,
            jti="benchmark-proof-0000000000000000",
            expires_at=expiry,
        )
        replay_latency = (time.perf_counter() - before) * 1000
        if replay_accepted:
            raise RuntimeError("replayed benchmark proof was accepted")

        return {
            "samples": samples,
            "accepted_proof_operations": {
                "steady_state": "1 INSERT",
                "cleanup": "1 DELETE amortized per configured cleanup interval",
            },
            "elapsed_seconds": round(elapsed, 6),
            "throughput_proofs_per_second": round(samples / elapsed, 1),
            "accepted_write_latency_ms": {
                "median": round(statistics.median(latencies), 4),
                "p95": round(percentile(latencies, 0.95), 4),
                "p99": round(percentile(latencies, 0.99), 4),
            },
            "replay_rejection_latency_ms": round(replay_latency, 4),
            "sqlite_file_bytes": {
                "baseline": baseline_size,
                "with_rows": final_size,
                "increment": final_size - baseline_size,
                "increment_per_proof": round((final_size - baseline_size) / samples, 2),
            },
        }
    finally:
        adapter.close()
        os.unlink(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=10_000)
    arguments = parser.parse_args()
    if arguments.samples <= 0:
        parser.error("--samples must be greater than zero")
    print(json.dumps(asyncio.run(benchmark(arguments.samples)), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
