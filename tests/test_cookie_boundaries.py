"""Cross-scheme cookie acceptance boundaries shared by every auth flow."""

import pytest
from hayate import Request

from hayate_auth import session
from hayate_auth.authorization_server import AS_COOKIE_BASE
from hayate_auth.oauth import STATE_COOKIE_BASE
from hayate_auth.passkey import CHALLENGE_COOKIE_BASE as PASSKEY_COOKIE_BASE
from hayate_auth.two_factor import CHALLENGE_COOKIE_BASE as TWO_FACTOR_COOKIE_BASE


@pytest.mark.parametrize(
    "base_name",
    (
        session.COOKIE_BASE,
        STATE_COOKIE_BASE,
        AS_COOKIE_BASE,
        PASSKEY_COOKIE_BASE,
        TWO_FACTOR_COOKIE_BASE,
    ),
)
def test_cookie_reader_accepts_only_the_name_for_the_request_scheme(base_name):
    bare = f"{base_name}=plain"
    host = f"__Host-{base_name}=secure"

    assert (
        session.read_scheme_bound_cookie(
            Request("https://localhost/", headers={"cookie": f"{bare}; {host}"}),
            base_name,
        )
        == "secure"
    )
    assert (
        session.read_scheme_bound_cookie(
            Request("http://localhost/", headers={"cookie": f"{host}; {bare}"}),
            base_name,
        )
        == "plain"
    )
    assert (
        session.read_scheme_bound_cookie(
            Request("https://localhost/", headers={"cookie": bare}),
            base_name,
        )
        is None
    )
    assert (
        session.read_scheme_bound_cookie(
            Request("http://localhost/", headers={"cookie": host}),
            base_name,
        )
        is None
    )
