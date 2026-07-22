"""CPython baseline for the KDF spike (run directly: uv run python baseline.py).

Measures hashlib.pbkdf2_hmac / hashlib.scrypt on this machine and checks the
same RFC 7914 §11 vectors the worker checks, so the cross-runtime
interoperability claim (DESIGN §17-3) rests on identical known answers.
"""

import hashlib
import json
import statistics
import time

from entry import KAT_VECTORS

OWASP_PBKDF2_SHA256_ITERS = 600_000
OWASP_SCRYPT = {"n": 2**17, "r": 8, "p": 1}  # 64 MiB


def timed(fn, rounds: int = 5) -> dict:
    samples = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000)
    return {
        "median_ms": round(statistics.median(samples), 1),
        "min_ms": round(min(samples), 1),
        "max_ms": round(max(samples), 1),
    }


def main() -> None:
    out: dict = {}

    kat = []
    for vec in KAT_VECTORS:
        derived = hashlib.pbkdf2_hmac(
            "sha256", vec["password"], vec["salt"], vec["iterations"], dklen=64
        )
        kat.append({"iterations": vec["iterations"], "match": derived.hex() == vec["expected"]})
    out["kat"] = kat

    for iters in (100_000, 300_000, 600_000, 1_000_000):
        out[f"pbkdf2_sha256_{iters}"] = timed(
            lambda i=iters: hashlib.pbkdf2_hmac("sha256", b"pw", b"salt0123456789ab", i)
        )

    out["scrypt_n17_r8_p1"] = timed(
        lambda: hashlib.scrypt(b"pw", salt=b"salt0123456789ab", **OWASP_SCRYPT, maxmem=256 * 2**20)
    )

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
