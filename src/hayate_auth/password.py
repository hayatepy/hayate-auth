"""Password length and blocklist policy for every password-setting path."""

from __future__ import annotations

import asyncio
import unicodedata
from collections.abc import Awaitable
from dataclasses import dataclass
from typing import Literal, Protocol

MIN_LENGTH = 8
MAX_LENGTH = 256
COMPROMISED_PASSWORD = "Password is commonly used or has been compromised"

# A deliberately compact online-guessing blocklist, not a replacement for an
# injected breach corpus. NIST SP 800-63B-4 discourages excessively large
# built-in lists; deployments can add service-specific values or a current
# breached-password checker through ``PasswordPolicy``.
COMMON_PASSWORDS = frozenset(
    {
        "11111111",
        "12345678",
        "123456789",
        "1234567890",
        "12341234",
        "1q2w3e4r",
        "65432100",
        "87654321",
        "abc12345",
        "admin123",
        "baseball",
        "basketball",
        "changeme",
        "computer",
        "correcthorsebatterystaple",
        "dragon",
        "football",
        "iloveyou",
        "jennifer",
        "letmein",
        "master",
        "michael",
        "monkey",
        "password",
        "password1",
        "password12",
        "password123",
        "passw0rd",
        "p@ssw0rd",
        "p@ssword",
        "princess",
        "qwerty123",
        "qwertyuiop",
        "secret123",
        "shadow",
        "starwars",
        "sunshine",
        "superman",
        "trustno1",
        "whatever",
        "welcome",
        "welcome1",
        "zaq12wsx",
    }
)


class CompromisedPasswordChecker(Protocol):
    """An app-owned async lookup; True means the password must be rejected."""

    def __call__(self, password: str) -> Awaitable[bool]: ...


class PasswordPolicyUnavailable(Exception):
    """The configured compromised-password checker could not decide safely."""


def _blocklist_key(password: str) -> str:
    return unicodedata.normalize("NFKC", password).casefold()


@dataclass(frozen=True)
class PasswordPolicy:
    """Local common-password baseline plus an optional async breach checker.

    The local list is always evaluated first, avoiding needless network
    disclosure. Configured checker failures reject with HTTP 503 by default;
    ``checker_failure="allow"`` is an explicit availability-over-enforcement
    choice.
    """

    compromised_checker: CompromisedPasswordChecker | None = None
    common_passwords: frozenset[str] = COMMON_PASSWORDS
    checker_failure: Literal["reject", "allow"] = "reject"
    checker_timeout: float = 2.0

    def __post_init__(self) -> None:
        if self.checker_failure not in ("reject", "allow"):
            raise ValueError("checker_failure must be 'reject' or 'allow'")
        if self.checker_timeout <= 0:
            raise ValueError("checker_timeout must be greater than zero")
        try:
            normalized = frozenset(_blocklist_key(value) for value in self.common_passwords)
        except (AttributeError, TypeError):
            raise ValueError("common_passwords must contain only strings") from None
        object.__setattr__(self, "common_passwords", normalized)

    async def error(self, password: object) -> str | None:
        """Return a user-facing rejection reason, or None when acceptable."""
        if (error := password_error(password)) is not None:
            return error
        assert isinstance(password, str)
        if _blocklist_key(password) in self.common_passwords:
            return COMPROMISED_PASSWORD
        if self.compromised_checker is None:
            return None
        try:
            async with asyncio.timeout(self.checker_timeout):
                compromised = await self.compromised_checker(password)
            if not isinstance(compromised, bool):
                raise TypeError("compromised password checker must return bool")
        except Exception as exc:
            if self.checker_failure == "allow":
                return None
            raise PasswordPolicyUnavailable from exc
        return COMPROMISED_PASSWORD if compromised else None


def password_error(password: object) -> str | None:
    """None when acceptable, else a human-readable reason."""
    if not isinstance(password, str):
        return "Password must be a string"
    if len(password) < MIN_LENGTH:
        return f"Password must be at least {MIN_LENGTH} characters"
    if len(password) > MAX_LENGTH:
        return f"Password must be at most {MAX_LENGTH} characters"
    return None


def email_error(email: object) -> str | None:
    """Minimal, standards-agnostic sanity check; real validation is the
    verification email's job (v0.2)."""
    if not isinstance(email, str):
        return "Email must be a string"
    email = email.strip()
    if not 3 <= len(email) <= 254 or "@" not in email[1:-1]:
        return "Email address looks invalid"
    return None


def normalize_email(email: str) -> str:
    return email.strip().lower()
