"""KDF spike: measure WebCrypto PBKDF2 on workerd (hayate-auth DESIGN §18).

Disposable code — findings land in docs/research/kdf.md.

    uv sync && uv run pywrangler dev    # local workerd on :8787

Routes:
    /info                     runtime + hashlib capability probe
    /pbkdf2?iters=N&rounds=M  time WebCrypto deriveBits PBKDF2-HMAC-SHA256
    /kat                      RFC 7914 §11 known-answer vectors (correctness)
"""

import time

from hayate import Context, Hayate
from hayate.adapters.workers import to_workers

app = Hayate()

PASSWORD = b"correct horse battery staple"
SALT = b"0123456789abcdef"

# RFC 7914 §11 PBKDF2-HMAC-SHA-256 test vectors (dkLen=64).
KAT_VECTORS = [
    {
        "password": b"passwd",
        "salt": b"salt",
        "iterations": 1,
        "expected": (
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
            "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        ),
    },
    {
        "password": b"Password",
        "salt": b"NaCl",
        "iterations": 80000,
        "expected": (
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
            "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
        ),
    },
]


def _hashlib_probe() -> dict:
    """Existence *and* usability of the OpenSSL-backed KDFs (DESIGN §8)."""
    import hashlib

    out: dict = {name: hasattr(hashlib, name) for name in ("scrypt", "pbkdf2_hmac")}
    try:
        hashlib.pbkdf2_hmac("sha256", b"pw", b"salt", 10)
        out["pbkdf2_hmac_call"] = "ok"
    except Exception as e:  # pragma: no cover - probe
        out["pbkdf2_hmac_call"] = f"{type(e).__name__}: {e}"
    try:
        hashlib.scrypt(b"pw", salt=b"salt", n=16384, r=8, p=1)
        out["scrypt_call"] = "ok"
    except Exception as e:  # pragma: no cover - probe
        out["scrypt_call"] = f"{type(e).__name__}: {e}"
    try:
        import hmac

        hmac.new(b"k", b"msg", "sha256").hexdigest()
        out["hmac_sha256_call"] = "ok"
    except Exception as e:  # pragma: no cover - probe
        out["hmac_sha256_call"] = f"{type(e).__name__}: {e}"
    return out


async def _webcrypto_pbkdf2(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    import js
    from pyodide.ffi import to_js

    key = await js.crypto.subtle.importKey(
        "raw", to_js(password), "PBKDF2", False, to_js(["deriveBits"])
    )
    algo = to_js(
        {"name": "PBKDF2", "hash": "SHA-256", "salt": salt, "iterations": iterations},
        dict_converter=js.Object.fromEntries,
    )
    bits = await js.crypto.subtle.deriveBits(algo, key, dklen * 8)
    return bytes(js.Uint8Array.new(bits).to_py())


@app.get("/info")
async def info(c: Context):
    import sys

    return c.json({"python": sys.version, "hashlib": _hashlib_probe()})


@app.get("/pbkdf2")
async def pbkdf2_route(c: Context):
    """Time WebCrypto PBKDF2. Both clocks are recorded because Workers
    freezes timers during CPU work (Spectre mitigation) — whether an
    awaited subtle.deriveBits advances them is itself a spike question."""
    import js

    iters = int(c.req.query("iters") or "600000")
    rounds = int(c.req.query("rounds") or "3")

    samples = []
    for _ in range(rounds):
        perf0 = time.perf_counter()
        date0 = js.Date.now()
        derived = await _webcrypto_pbkdf2(PASSWORD, SALT, iters, 32)
        perf1 = time.perf_counter()
        date1 = js.Date.now()
        samples.append(
            {
                "perf_counter_ms": round((perf1 - perf0) * 1000, 3),
                "date_now_ms": date1 - date0,
            }
        )

    return c.json(
        {
            "iterations": iters,
            "derived_hex_prefix": derived[:8].hex(),
            "samples": samples,
        }
    )


@app.get("/hashlib-pbkdf2")
async def hashlib_pbkdf2_route(c: Context):
    """Time the wasm-compiled hashlib.pbkdf2_hmac (exists on this Pyodide!)."""
    import hashlib

    import js

    iters = int(c.req.query("iters") or "600000")
    rounds = int(c.req.query("rounds") or "3")

    samples = []
    for _ in range(rounds):
        perf0 = time.perf_counter()
        date0 = js.Date.now()
        derived = hashlib.pbkdf2_hmac("sha256", PASSWORD, SALT, iters)
        perf1 = time.perf_counter()
        date1 = js.Date.now()
        samples.append(
            {
                "perf_counter_ms": round((perf1 - perf0) * 1000, 3),
                "date_now_ms": date1 - date0,
            }
        )

    return c.json(
        {
            "iterations": iters,
            "derived_hex_prefix": derived[:8].hex(),
            "samples": samples,
        }
    )


@app.get("/hashlib-scrypt")
async def hashlib_scrypt_route(c: Context):
    """Time the wasm-compiled hashlib.scrypt; does 64 MiB fit the wasm heap?"""
    import hashlib

    import js

    n_exp = int(c.req.query("n") or "17")
    rounds = int(c.req.query("rounds") or "3")

    samples = []
    try:
        for _ in range(rounds):
            perf0 = time.perf_counter()
            date0 = js.Date.now()
            derived = hashlib.scrypt(
                PASSWORD, salt=SALT, n=2**n_exp, r=8, p=1, maxmem=256 * 2**20
            )
            perf1 = time.perf_counter()
            date1 = js.Date.now()
            samples.append(
                {
                    "perf_counter_ms": round((perf1 - perf0) * 1000, 3),
                    "date_now_ms": date1 - date0,
                }
            )
    except Exception as e:
        return c.json({"n": 2**n_exp, "error": f"{type(e).__name__}: {e}", "samples": samples})

    return c.json(
        {
            "n": 2**n_exp,
            "derived_hex_prefix": derived[:8].hex(),
            "samples": samples,
        }
    )


@app.get("/hashlib-kat")
async def hashlib_kat_route(c: Context):
    """Same RFC 7914 vectors through the wasm hashlib.pbkdf2_hmac."""
    import hashlib

    results = []
    for vec in KAT_VECTORS:
        derived = hashlib.pbkdf2_hmac(
            "sha256", vec["password"], vec["salt"], vec["iterations"], dklen=64
        )
        results.append({"iterations": vec["iterations"], "match": derived.hex() == vec["expected"]})
    return c.json({"vectors": results, "all_match": all(r["match"] for r in results)})


@app.get("/kat")
async def kat_route(c: Context):
    """RFC 7914 §11 vectors: does WebCrypto produce the canonical bytes?"""
    results = []
    for vec in KAT_VECTORS:
        derived = await _webcrypto_pbkdf2(vec["password"], vec["salt"], vec["iterations"], 64)
        results.append(
            {
                "iterations": vec["iterations"],
                "match": derived.hex() == vec["expected"],
                "derived": derived.hex(),
            }
        )
    return c.json({"vectors": results, "all_match": all(r["match"] for r in results)})


try:
    Default = to_workers(app)
except ModuleNotFoundError:  # imported on plain CPython (baseline.py reuses KAT_VECTORS)
    Default = None
