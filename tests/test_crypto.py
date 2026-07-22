"""KDF backends: PHC round trips, cross-algorithm dispatch, defaults."""

import pytest

from hayate_auth import Pbkdf2Backend, ScryptBackend, UnsupportedHashError, default_backend
from hayate_auth.crypto import verify_phc

FAST_SCRYPT = ScryptBackend(log_n=12)
FAST_PBKDF2 = Pbkdf2Backend(iterations=1_000)


async def test_scrypt_round_trip():
    stored = await FAST_SCRYPT.hash_password("hunter2hunter2")
    assert stored.startswith("$scrypt$ln=12,r=8,p=1$")
    assert await FAST_SCRYPT.verify_password("hunter2hunter2", stored)
    assert not await FAST_SCRYPT.verify_password("wrong password", stored)


async def test_pbkdf2_round_trip():
    stored = await FAST_PBKDF2.hash_password("hunter2hunter2")
    assert stored.startswith("$pbkdf2-sha256$i=1000$")
    assert await FAST_PBKDF2.verify_password("hunter2hunter2", stored)
    assert not await FAST_PBKDF2.verify_password("wrong password", stored)


async def test_verification_dispatches_on_stored_algorithm():
    """Hashes written by either backend verify through the other — the
    cross-runtime interoperability the spike established."""
    scrypt_hash = await FAST_SCRYPT.hash_password("swordfish-swordfish")
    pbkdf2_hash = await FAST_PBKDF2.hash_password("swordfish-swordfish")
    assert await FAST_PBKDF2.verify_password("swordfish-swordfish", scrypt_hash)
    assert await FAST_SCRYPT.verify_password("swordfish-swordfish", pbkdf2_hash)


async def test_unknown_algorithm_raises():
    with pytest.raises(UnsupportedHashError):
        await verify_phc("pw", "$argon2id$v=19$c2FsdA$aGFzaA")


async def test_garbage_stored_value_is_false():
    assert not await verify_phc("pw", "not-a-phc-string")
    assert not await verify_phc("pw", "")


async def test_salts_are_unique():
    one = await FAST_SCRYPT.hash_password("same password!")
    two = await FAST_SCRYPT.hash_password("same password!")
    assert one != two
    assert await FAST_SCRYPT.verify_password("same password!", one)
    assert await FAST_SCRYPT.verify_password("same password!", two)


def test_default_backend_prefers_scrypt():
    # CPython always has hashlib.scrypt; the PBKDF2 fallback path is for
    # pre-OpenSSL Pyodide builds (research/kdf.md).
    assert isinstance(default_backend(), ScryptBackend)


async def test_production_parameters_match_owasp():
    backend = ScryptBackend()
    assert backend.log_n == 17 and backend.r == 8 and backend.p == 1
    assert Pbkdf2Backend().iterations == 600_000
