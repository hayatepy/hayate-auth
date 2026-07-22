# Security Policy

hayate-auth is **alpha software and has not received an external security
audit**. Do not run it as the sole protection for production credentials yet.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on this repository
(Security → Report a vulnerability). Reports are acknowledged within 72 hours.
Please do not open public issues for suspected vulnerabilities.

## Scope and design commitments

- No self-built cryptographic primitives: all KDF/HMAC work goes through
  `hashlib` / `hmac` / WebCrypto (DESIGN §8).
- Passwords are stored as salted scrypt (OWASP parameters) or
  PBKDF2-HMAC-SHA256 (600k) PHC strings; sessions are stored only as SHA-256
  digests of 256-bit random tokens.
- Attack regressions (session fixation, replay after sign-out, expiry,
  enumeration timing, CSRF) are part of the test suite and never removed.
- Rate limiting is explicitly the embedding application's responsibility;
  deployments must throttle `/api/auth/*`.
