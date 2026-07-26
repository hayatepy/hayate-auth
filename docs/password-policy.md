# Common and compromised password policy

Every password-establishment path uses the same `PasswordPolicy`:

- `POST /api/auth/sign-up/email`;
- `POST /api/auth/reset-password`;
- authenticated `POST /api/auth/change-password`.

The default policy has no network behavior. It enforces the existing length
rules and a compact, deterministic blocklist of common online guesses.
[NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
requires prospective passwords to be checked against commonly used, expected,
or compromised values, while also cautioning that an excessively large
built-in blocklist adds little benefit. Deployments can therefore extend the
local set and inject a current breach-corpus lookup.

## Inject an async checker

```python
from hayate_auth import Auth, COMMON_PASSWORDS, PasswordPolicy


async def compromised(password: str) -> bool:
    # Query an app-owned local corpus or privacy-preserving provider.
    # Never log or persist the plaintext value.
    return await breach_store.contains(password)


auth = Auth(
    secret=AUTH_SECRET,
    adapter=adapter,
    password_policy=PasswordPolicy(
        compromised_checker=compromised,
        common_passwords=COMMON_PASSWORDS
        | frozenset(
            {
                "your product name",
                "your company name",
                "your default onboarding password",
            }
        ),
        checker_timeout=2.0,
        checker_failure="reject",
    ),
)
```

The configured local set replaces the built-in set, which makes policy
versioning deterministic. Union it with `COMMON_PASSWORDS`, as above, when a
deployment wants to extend the baseline.

The checker runs at most once after the local check and must return a real
boolean. Its exception, timeout, or invalid response produces an HTTP 503
without mutating credentials. `checker_failure="allow"` is available only as
an explicit availability-over-enforcement choice.

## Privacy-safe Pwned Passwords shape

[Have I Been Pwned's Pwned Passwords range API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
does not need the plaintext. A checker should:

1. UTF-8 encode and SHA-1 hash the complete submitted password locally.
2. Send only the first five hexadecimal hash characters to
   `https://api.pwnedpasswords.com/range/{prefix}`.
3. Set `Add-Padding: true`, identify the application with `User-Agent`, and
   refuse redirects.
4. Bound the HTTP status, response size, parsing work, and timeout.
5. Compare the remaining 35-character suffix locally and treat a positive
   count as compromised.

SHA-1 here is a range identifier required by that API, not password storage;
hayate-auth continues to store account passwords with its salted,
cost-parameterized password KDF. Do not perform incremental range requests as
the user types. A downloaded offline corpus is preferable when the deployment
must have zero network disclosure or deterministic availability.

## Change password

The authenticated endpoint follows
[Better Auth's request shape](https://www.better-auth.com/docs/concepts/users-accounts#change-password):

```json
{
  "currentPassword": "current value",
  "newPassword": "new unique value",
  "revokeOtherSessions": true
}
```

The current password is reverified before the external checker runs.
`revokeOtherSessions` preserves the caller's current session and removes the
other sessions visible at the time of the update. Password reset remains the
stronger recovery operation and revokes every current session.
