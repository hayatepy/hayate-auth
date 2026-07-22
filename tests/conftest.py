import json

import pytest
from hayate import Request

from hayate_auth import Auth, ScryptBackend
from hayate_auth.adapters.sqlite import SQLiteAdapter


@pytest.fixture
def adapter():
    a = SQLiteAdapter(":memory:")
    a.create_tables()
    yield a
    a.close()


@pytest.fixture
def auth(adapter):
    # Small-N scrypt keeps the suite fast; production defaults are covered
    # in test_crypto.py.
    return Auth(secret="test-secret", adapter=adapter, crypto=ScryptBackend(log_n=12))


def request_json(
    path: str,
    data=None,
    *,
    method: str = "POST",
    cookie: str | None = None,
    origin: str | None = None,
    headers: dict[str, str] | None = None,
    scheme: str = "http",
) -> Request:
    merged = {"content-type": "application/json", **(headers or {})}
    if cookie is not None:
        merged["cookie"] = cookie
    if origin is not None:
        merged["origin"] = origin
    body = None if data is None else json.dumps(data)
    return Request(f"{scheme}://localhost{path}", method=method, headers=merged, body=body)


def cookie_pair(response) -> str:
    """Extract "name=value" from the first Set-Cookie for replay."""
    header = response.headers.get("set-cookie")
    assert header, "expected a Set-Cookie header"
    return header.split(";", 1)[0]
