# OWASP ASVS 5.0.0 control ledger

This is a test-backed ledger of selected controls relevant to hayate-auth
v0.10.1. It is not an OWASP certification, an assertion of a complete ASVS
level, or a substitute for an independent review. Requirement references use
the OWASP-recommended versioned form and are validated against the official
ASVS 5.0.0 CSV pinned by the v0.9.1 base in `audit/target.toml`; the current
target and expected counts are pinned in `audit/amendments/v0.10.1.toml`.

Statuses are **covered** (implemented and regression-tested), **external**
(required but deliberately delegated to the embedding deployment), and
**gap** (applicable work not implemented). Controls outside this library's
scope are not counted. The audit threat model lists additional applicable
controls that are not yet ledger claims.

## V6 — Authentication

| Control claim | ASVS 5.0.0 reference | Status | Evidence |
|---|---|---|---|
| User-set passwords require at least 8 characters | `v5.0.0-6.2.1` | covered | `password.py`, `tests/test_email_flow.py` |
| Password policy imposes no character-class composition rules | `v5.0.0-6.2.5` | covered | `password.py` |
| Passwords of at least 64 characters are accepted (limit 256) | `v5.0.0-6.2.9` | covered | `password.py` |
| A top-3000 policy-matching password set and current breached-password corpus must be supplied by the deployment; the built-in compact baseline alone does not meet these controls | `v5.0.0-6.2.4`, `v5.0.0-6.2.12` | external | `docs/password-policy.md`, `tests/test_password_policy.py::test_injected_checker_applies_to_signup_reset_and_change`, `::test_checker_failure_is_fail_closed_and_does_not_mutate` |
| Passwords use a salted, computationally intensive KDF at documented cost | `v5.0.0-11.4.2` | covered | `crypto/`, `tests/test_crypto.py::test_production_parameters_match_owasp` |
| Secret/hash comparisons use constant-time library operations | `v5.0.0-11.2.4` | covered | `hmac.compare_digest` in `crypto/` and authorization-server code |
| Bad credentials return a generic response that does not identify a user | `v5.0.0-6.3.8` | covered | `tests/test_email_flow.py::test_wrong_password_and_unknown_user_are_identical_401s` |
| Unknown-user sign-in performs a dummy KDF to reduce timing enumeration | `v5.0.0-6.3.8` | covered | `tests/test_attacks.py::test_unknown_user_still_burns_a_kdf` |
| Brute-force and credential-stuffing controls are documented as required deployment controls | `v5.0.0-6.1.1` | external | `README.md`, `SECURITY.md`, `audit/THREAT_MODEL.md` |
| Password reset uses a short-lived, one-shot value and revokes sessions | `v5.0.0-6.4.3` | covered | `tests/test_verification.py` |
| Email activation values are CSPRNG-generated, short-lived, and one-shot | `v5.0.0-6.4.1` | covered | `verification.py`, `tests/test_verification.py::test_email_verification_flow` |
| OAuth client transactions bind state and PKCE verifier to the initiating user-agent session | `v5.0.0-10.1.2` | covered | `oauth.py`, `tests/test_oauth.py::test_state_mismatch_is_rejected` |
| Unverified provider email does not auto-link an existing account | `v5.0.0-6.3.8` | covered | `tests/test_oauth.py::test_unverified_email_does_not_hijack_existing_user` |
| Password sign-in can require a second TOTP factor | `v5.0.0-6.3.3` | covered | `two_factor.py`, `tests/test_totp.py` |
| Password success alone cannot create a session when TOTP is enabled | `v5.0.0-6.3.3` | covered | `tests/test_totp.py::test_password_alone_never_yields_a_session_with_2fa` |
| An accepted TOTP time step is atomically single-use and cannot roll back to an older adjacent-window step | `v5.0.0-6.5.1` | covered | `tests/test_totp.py::test_totp_step_is_single_use_and_state_never_rolls_back`, `::test_concurrent_totp_redemption_has_exactly_one_winner` |
| Magic-link values are CSPRNG-generated, hashed at rest, short-lived, and one-shot | `v5.0.0-6.5.2`, `v5.0.0-6.5.3`, `v5.0.0-6.5.5` | covered | `tests/test_magic_link.py::test_token_is_single_use`, `::test_expired_token_is_rejected` |
| Magic-link requests do not disclose whether an account exists | `v5.0.0-6.3.8` | covered | `tests/test_magic_link.py::test_unknown_and_known_emails_answer_identically` |
| Magic-link callback URLs are restricted to the configured origin | `v5.0.0-1.2.2` | covered | `tests/test_magic_link.py::test_offsite_callback_url_is_rejected` |
| Purpose prefixes prevent using a magic-link value as a reset/verification value | `v5.0.0-2.2.1` | covered | `tests/test_magic_link.py::test_magic_token_cannot_pass_as_reset_token` |
| WebAuthn passkeys bind origin, RP ID, challenge, and user intent | `v5.0.0-6.3.3` | covered | `passkey.py`, `tests/test_passkey.py::test_wrong_origin_is_rejected` |
| Passkey sign-counter regression is rejected | `v5.0.0-6.3.3` | covered | `tests/test_passkey.py::test_sign_counter_rollback_is_rejected` |
| Passkey challenges are purpose-bound, short-lived, and HMAC-authenticated | `v5.0.0-11.4.3`, `v5.0.0-11.5.1` | covered | `tests/test_passkey.py::test_registration_needs_session_and_challenge` |
| A replayed registration response cannot duplicate a credential | `v5.0.0-6.5.1` | covered | `tests/test_passkey.py::test_replayed_attestation_cannot_register_twice` |
| Passkey management operations are scoped to the authenticated owner | `v5.0.0-8.2.2` | covered | `tests/test_passkey.py::test_delete_is_owner_scoped` |

## V7 — Session management

| Control claim | ASVS 5.0.0 reference | Status | Evidence |
|---|---|---|---|
| Session reference tokens are generated by a CSPRNG with 256 bits of entropy | `v5.0.0-7.2.3`, `v5.0.0-11.5.1` | covered | `secrets.token_urlsafe(32)` in `session.py` |
| Session verification is server-side and the database stores only a token digest | `v5.0.0-7.2.1` | covered | `session.py`, `tests/test_attacks.py::test_database_never_stores_the_raw_token` |
| Session cookies are HttpOnly | `v5.0.0-3.3.4` | covered | `tests/test_email_flow.py` |
| HTTPS session cookies are Secure and use the `__Host-` prefix | `v5.0.0-3.3.1`, `v5.0.0-3.3.3` | covered | `tests/test_email_flow.py::test_https_uses_host_prefix_and_secure` |
| Session cookies set an explicit SameSite policy | `v5.0.0-3.3.2` | covered | `session.py` |
| Authentication rotates and terminates the previous session token | `v5.0.0-7.2.4` | covered | `tests/test_attacks.py::test_sign_in_rotates_the_session_token` |
| Logout invalidates the server-side session | `v5.0.0-7.4.1` | covered | `tests/test_attacks.py::test_revoked_token_cannot_be_replayed` |
| Password reset terminates every active session for the user | `v5.0.0-7.4.3` | covered | `tests/test_verification.py::test_reset_revokes_every_session` |
| Absolute session expiry is enforced and expired rows are purged | `v5.0.0-7.3.2` | covered | `tests/test_attacks.py::test_expired_session_is_rejected_and_deleted` |
| Cookie-carried state changes validate origin and Fetch Metadata | `v5.0.0-3.5.1`, `v5.0.0-3.5.3` | covered | `csrf.py`, `tests/test_csrf.py` |
| Provider OAuth callback destinations reject cross-origin redirects | `v5.0.0-1.2.2` | covered | `tests/test_oauth.py::test_open_redirect_callback_url_is_rejected` |
| Idle timeout is enforced; fresh authenticated users can list sessions and revoke one, others, or all without exposing token material | `v5.0.0-7.3.1`, `v5.0.0-7.5.2` | covered | `tests/test_session_management.py::test_idle_timeout_uses_bounded_activity_touches`, `::test_list_and_revoke_sessions_without_token_material`, `::test_sensitive_session_management_requires_fresh_session` |

## V10 — OAuth authorization server and resource server

| Control claim | ASVS 5.0.0 reference | Status | Evidence |
|---|---|---|---|
| Redirect URIs use client-specific exact matching, with RFC 8252 loopback-port handling | `v5.0.0-10.4.1` | covered | `tests/test_authorization_server.py::test_authorize_unregistered_redirect_answers_directly`, `::test_authorize_loopback_port_may_vary` |
| Authorization codes are single-use and replay revokes tokens issued from the code | `v5.0.0-10.4.2` | covered | `::test_code_replay_revokes_the_tokens_it_issued` |
| Authorization codes are short-lived (five-minute default) and expiry is enforced | `v5.0.0-10.4.3` | covered | `::test_token_rejects_expired_code` |
| Only authorization-code and refresh grants are supported | `v5.0.0-10.4.4` | covered | metadata and `::test_unsupported_grant_type` |
| Refresh values rotate and reuse revokes the token family | `v5.0.0-10.4.5` | covered | `::test_refresh_rotation_and_reuse_detection` |
| PKCE is required for every client and only S256 is accepted | `v5.0.0-10.4.6` | covered | `::test_authorize_error_redirects`, `::test_token_rejects_wrong_pkce_verifier` |
| Codes and refresh values are bound to the requesting client | `v5.0.0-10.4.10` | covered | `::test_token_rejects_another_clients_code`, `::test_refresh_rejects_other_clients_token` |
| Confidential clients must use their registered authentication method | `v5.0.0-10.4.10` | covered | `::test_confidential_client_authentication`, `::test_auth_method_must_match_registration` |
| Codes, access/refresh values, and client secrets are stored only as SHA-256 digests | `v5.0.0-11.4.1` | covered | `::test_register_confidential_client_returns_secret_once`, `authorization_server.py` |
| Resource servers enforce the exact audience and delegated scope | `v5.0.0-10.3.1`, `v5.0.0-10.3.2` | covered | `::test_token_resource_must_match_the_code`, `::test_verifier_factory_enforces_resource` |
| Consent is user/client-bound and requested again when scope widens | `v5.0.0-10.7.1`, `v5.0.0-10.7.2` | covered | `::test_consent_cookie_is_bound_to_the_user`, `::test_authorize_widening_scope_needs_fresh_consent` |
| Guarded atomic transitions prevent concurrent code/refresh redemption from minting multiple live families | `v5.0.0-10.4.2`, `v5.0.0-10.4.5` | covered | `::test_concurrent_code_exchange_mints_exactly_one_token_family`, `::test_concurrent_refresh_mints_exactly_one_replacement` |
| Token responses are marked `Cache-Control: no-store` | `v5.0.0-14.3.2` | covered | `::test_token_response_is_uncacheable` |
| Open dynamic registration requires deployment-level anti-automation | `v5.0.0-10.4.7`, `v5.0.0-6.1.1` | external | URI/metadata validation is in-core; throttling is an infrastructure requirement |
| Token-family and end-user consent revocation are private, immediate, and race-safe; authenticated resource servers can introspect only their exact resource | `v5.0.0-10.4.9`, `v5.0.0-10.7.3` | covered | `tests/test_authorization_server.py::test_revocation_is_idempotent_private_and_family_wide`, `::test_introspection_is_resource_bound_authenticated_and_private`, `::test_consent_revocation_racing_code_exchange_cannot_leave_a_live_token` |
| The server-wide DPoP profile issues only key-bound access tokens, while request-aware resource verification enforces key, request, token-hash, and replay binding | `v5.0.0-10.3.5`, `v5.0.0-10.4.14` | covered | `tests/test_authorization_server.py::test_server_wide_dpop_policy_prevents_bearer_issuance_for_every_client`, `tests/test_dpop.py::test_valid_resource_proof_is_key_and_access_token_bound`, `::test_proof_replay_is_rejected_even_under_concurrency`, `scripts/check_current_workerd.sh` |

## Applicable limitations not claimed as gaps

The password row is deliberately external rather than covered: the built-in
set has fewer than the 3000 values required by `v5.0.0-6.2.4`, and a live
breach corpus is injected. DPoP coverage is explicitly limited to the
server-wide profile; the default Bearer compatibility profile does not meet
those sender-constraint controls. Email magic links do not satisfy the ASVS
Level 3 prohibition on email authentication
(`v5.0.0-6.3.6`). Deployment throttling and these profile boundaries are
tracked in `audit/THREAT_MODEL.md`; this ledger does not claim that all ASVS
controls or an ASVS level have been assessed.

**Ratchet: 50 covered, 3 external, 0 gap (53 selected claims).**
