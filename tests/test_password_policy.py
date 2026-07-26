import asyncio

import pytest

from conftest import cookie_pair, request_json
from hayate_auth import Auth, PasswordPolicy, ScryptBackend
from hayate_auth.adapter import Where

SIGNUP = "/api/auth/sign-up/email"
SIGNIN = "/api/auth/sign-in/email"
FORGET = "/api/auth/forget-password"
RESET = "/api/auth/reset-password"
CHANGE = "/api/auth/change-password"


class Checker:
    def __init__(self, compromised=(), *, failure: Exception | None = None) -> None:
        self.compromised = set(compromised)
        self.failure = failure
        self.seen: list[str] = []

    async def __call__(self, password: str) -> bool:
        self.seen.append(password)
        if self.failure is not None:
            raise self.failure
        return password in self.compromised


class ResetOutbox:
    def __init__(self) -> None:
        self.tokens: list[str] = []

    async def send(self, _user, token: str) -> None:
        self.tokens.append(token)


def make_auth(adapter, policy: PasswordPolicy, outbox: ResetOutbox | None = None) -> Auth:
    return Auth(
        secret="password-policy-test",
        adapter=adapter,
        crypto=ScryptBackend(log_n=12),
        password_policy=policy,
        send_reset_password=outbox.send if outbox is not None else None,
    )


@pytest.mark.parametrize(
    "password",
    ["password", "\uff30\uff21\uff33\uff33\uff37\uff2f\uff32\uff24"],
)
async def test_default_local_blocklist_rejects_common_normalized_values(auth, adapter, password):
    response = await auth.fetch(
        request_json(SIGNUP, {"email": "common@example.com", "password": password})
    )
    assert response.status == 400
    assert (await response.json())["title"] == "Password is commonly used or has been compromised"
    assert await adapter.find_one("user", [Where("email", "common@example.com")]) is None


async def test_signup_rejection_does_not_reveal_existing_email(auth):
    await auth.fetch(
        request_json(
            SIGNUP,
            {"email": "existing@example.com", "password": "unique signup password"},
        )
    )
    existing = await auth.fetch(
        request_json(SIGNUP, {"email": "existing@example.com", "password": "password"})
    )
    absent = await auth.fetch(
        request_json(SIGNUP, {"email": "absent@example.com", "password": "password"})
    )
    assert existing.status == absent.status == 400
    assert await existing.text() == await absent.text()


async def test_injected_checker_applies_to_signup_reset_and_change(adapter):
    checker = Checker({"breached signup value", "breached reset value", "breached change value"})
    outbox = ResetOutbox()
    auth = make_auth(
        adapter,
        PasswordPolicy(compromised_checker=checker),
        outbox,
    )

    rejected_signup = await auth.fetch(
        request_json(
            SIGNUP,
            {"email": "blocked@example.com", "password": "breached signup value"},
        )
    )
    assert rejected_signup.status == 400

    signup = await auth.fetch(
        request_json(
            SIGNUP,
            {"email": "owner@example.com", "password": "initial unique password"},
        )
    )
    owner_cookie = cookie_pair(signup)
    await auth.fetch(request_json(FORGET, {"email": "owner@example.com"}))
    reset_token = outbox.tokens[-1]
    rejected_reset = await auth.fetch(
        request_json(
            RESET,
            {"token": reset_token, "password": "breached reset value"},
        )
    )
    assert rejected_reset.status == 400

    # Policy rejection does not burn the single-use reset credential.
    accepted_reset = await auth.fetch(
        request_json(
            RESET,
            {"token": reset_token, "password": "reset unique password"},
        )
    )
    assert accepted_reset.status == 200

    signed_in = await auth.fetch(
        request_json(
            SIGNIN,
            {"email": "owner@example.com", "password": "reset unique password"},
        )
    )
    current_cookie = cookie_pair(signed_in)
    rejected_change = await auth.fetch(
        request_json(
            CHANGE,
            {
                "currentPassword": "reset unique password",
                "newPassword": "breached change value",
            },
            cookie=current_cookie,
        )
    )
    assert rejected_change.status == 400
    assert checker.seen == [
        "breached signup value",
        "initial unique password",
        "breached reset value",
        "reset unique password",
        "breached change value",
    ]

    # The session created at sign-up was revoked by the completed reset.
    stale = await auth.fetch(
        request_json("/api/auth/get-session", method="GET", cookie=owner_cookie)
    )
    assert (await stale.json())["session"] is None


async def test_change_password_reauthenticates_and_can_revoke_other_sessions(adapter):
    auth = make_auth(adapter, PasswordPolicy())
    signup = await auth.fetch(
        request_json(
            SIGNUP,
            {"email": "change@example.com", "password": "initial unique password"},
        )
    )
    first_cookie = cookie_pair(signup)
    second_signin = await auth.fetch(
        request_json(
            SIGNIN,
            {"email": "change@example.com", "password": "initial unique password"},
        )
    )
    second_cookie = cookie_pair(second_signin)

    wrong = await auth.fetch(
        request_json(
            CHANGE,
            {
                "currentPassword": "wrong current password",
                "newPassword": "replacement unique password",
            },
            cookie=first_cookie,
        )
    )
    assert wrong.status == 401

    changed = await auth.fetch(
        request_json(
            CHANGE,
            {
                "currentPassword": "initial unique password",
                "newPassword": "replacement unique password",
                "revokeOtherSessions": True,
            },
            cookie=first_cookie,
        )
    )
    assert changed.status == 200
    assert (await changed.json())["user"]["email"] == "change@example.com"

    current = await auth.fetch(
        request_json("/api/auth/get-session", method="GET", cookie=first_cookie)
    )
    other = await auth.fetch(
        request_json("/api/auth/get-session", method="GET", cookie=second_cookie)
    )
    assert (await current.json())["session"] is not None
    assert (await other.json())["session"] is None

    old = await auth.fetch(
        request_json(
            SIGNIN,
            {"email": "change@example.com", "password": "initial unique password"},
        )
    )
    new = await auth.fetch(
        request_json(
            SIGNIN,
            {"email": "change@example.com", "password": "replacement unique password"},
        )
    )
    assert old.status == 401
    assert new.status == 200


async def test_change_password_requires_session_and_valid_current_password_before_checker(adapter):
    checker = Checker({"breached replacement value"})
    auth = make_auth(adapter, PasswordPolicy(compromised_checker=checker))
    signup = await auth.fetch(
        request_json(
            SIGNUP,
            {"email": "ordered@example.com", "password": "initial unique password"},
        )
    )
    cookie = cookie_pair(signup)
    checker.seen.clear()

    unauthenticated = await auth.fetch(
        request_json(
            CHANGE,
            {
                "currentPassword": "initial unique password",
                "newPassword": "breached replacement value",
            },
        )
    )
    wrong_current = await auth.fetch(
        request_json(
            CHANGE,
            {
                "currentPassword": "incorrect current password",
                "newPassword": "breached replacement value",
            },
            cookie=cookie,
        )
    )
    invalid_revoke_flag = await auth.fetch(
        request_json(
            CHANGE,
            {
                "currentPassword": "initial unique password",
                "newPassword": "breached replacement value",
                "revokeOtherSessions": "yes",
            },
            cookie=cookie,
        )
    )

    assert unauthenticated.status == 401
    assert wrong_current.status == 401
    assert invalid_revoke_flag.status == 400
    assert checker.seen == []


async def test_checker_failure_is_fail_closed_and_does_not_mutate(adapter):
    checker = Checker(failure=OSError("provider unavailable"))
    auth = make_auth(
        adapter,
        PasswordPolicy(compromised_checker=checker),
    )
    response = await auth.fetch(
        request_json(
            SIGNUP,
            {"email": "failure@example.com", "password": "otherwise unique password"},
        )
    )
    assert response.status == 503
    assert (await response.json())["title"] == "Password policy temporarily unavailable"
    assert await adapter.find_one("user", [Where("email", "failure@example.com")]) is None


async def test_checker_failure_does_not_consume_reset_token(adapter):
    checker = Checker()
    outbox = ResetOutbox()
    auth = make_auth(
        adapter,
        PasswordPolicy(compromised_checker=checker),
        outbox,
    )
    await auth.fetch(
        request_json(
            SIGNUP,
            {"email": "reset-failure@example.com", "password": "initial unique password"},
        )
    )
    await auth.fetch(request_json(FORGET, {"email": "reset-failure@example.com"}))
    reset_token = outbox.tokens[-1]
    checker.failure = OSError("provider unavailable")

    unavailable = await auth.fetch(
        request_json(
            RESET,
            {"token": reset_token, "password": "replacement unique password"},
        )
    )
    assert unavailable.status == 503

    checker.failure = None
    retry = await auth.fetch(
        request_json(
            RESET,
            {"token": reset_token, "password": "replacement unique password"},
        )
    )
    assert retry.status == 200


async def test_checker_failure_can_be_explicitly_fail_open(adapter):
    checker = Checker(failure=OSError("provider unavailable"))
    auth = make_auth(
        adapter,
        PasswordPolicy(
            compromised_checker=checker,
            checker_failure="allow",
        ),
    )
    response = await auth.fetch(
        request_json(
            SIGNUP,
            {"email": "available@example.com", "password": "otherwise unique password"},
        )
    )
    assert response.status == 200


async def test_checker_timeout_is_bounded(adapter):
    async def never_finishes(_password: str) -> bool:
        await asyncio.Event().wait()
        return False

    auth = make_auth(
        adapter,
        PasswordPolicy(
            compromised_checker=never_finishes,
            checker_timeout=0.01,
        ),
    )
    response = await auth.fetch(
        request_json(
            SIGNUP,
            {"email": "timeout@example.com", "password": "otherwise unique password"},
        )
    )
    assert response.status == 503


@pytest.mark.parametrize(
    "kwargs",
    [
        {"checker_failure": "sometimes"},
        {"checker_timeout": 0},
        {"common_passwords": frozenset({1})},
    ],
)
def test_policy_configuration_is_validated(kwargs):
    with pytest.raises(ValueError):
        PasswordPolicy(**kwargs)
