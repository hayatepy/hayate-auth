"""Credential policy per NIST SP 800-63B §5.1.1: length is the only rule.

At least 8 characters, no composition rules, and a generous upper bound so
passphrases and password managers are never punished.
"""

from __future__ import annotations

MIN_LENGTH = 8
MAX_LENGTH = 256


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
