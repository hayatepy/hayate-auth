# Session lifetime and management

hayate-auth keeps absolute lifetime, inactivity lifetime, write frequency, and
reauthentication freshness as separate controls:

```python
from datetime import timedelta

from hayate_auth import Auth

auth = Auth(
    secret=AUTH_SECRET,
    adapter=adapter,
    session_ttl=timedelta(days=7),
    session_idle_timeout=timedelta(days=1),
    session_touch_interval=timedelta(minutes=5),
    session_fresh_ttl=timedelta(days=1),
)
```

These are also the defaults.

- `session_ttl` is an absolute deadline fixed when the session is created.
- `session_idle_timeout` rejects a session whose last activity is too old.
  Set it to `None` only when the application deliberately disables inactivity
  expiry.
- `session_touch_interval` bounds persistence writes. Requests inside the
  interval validate the session without updating it.
- `session_fresh_ttl` controls sensitive session-management operations. A
  user with an older session must sign in again. Set it to `None` to disable
  this check.

The touch interval must be shorter than the inactivity timeout. A touch never
extends the absolute deadline.

## Concurrent activity

`last_active_at` is updated with one guarded `update_many()` operation using
the previously observed value. Concurrent requests can therefore produce only
one affected-row write for an interval. A losing request re-reads the
authoritative row: if another request revoked it, authentication fails instead
of reviving or accepting the removed session.

This preserves D1 efficiency without an in-memory lock, which would not work
across Workers isolates.

## End-user API

The paths follow
[Better Auth's session-management surface](https://www.better-auth.com/docs/concepts/session-management):

| Method and path | Effect |
|---|---|
| `GET /api/auth/list-sessions` | List the caller's active sessions |
| `POST /api/auth/revoke-session` | Revoke one owned session |
| `POST /api/auth/revoke-other-sessions` | Preserve current; revoke the rest |
| `POST /api/auth/revoke-sessions` | Revoke every session, including current |

All four require a fresh, authoritative session. Listing returns an array with
`id`, `user_id`, absolute expiry, last activity, creation time, IP address,
user agent, and a `current` boolean. Neither the opaque cookie token nor its
database digest is exposed.

Because hayate-auth deliberately never returns session tokens, single-session
revocation uses the public session ID:

```json
{
  "sessionId": "019c..."
}
```

The operation is constrained by both `sessionId` and the authenticated
`user_id`. An unknown or cross-user ID receives the same success response and
does not reveal whether the target exists. Revoking the current session or all
sessions also clears the caller's cookie.

## Administrative primitives

Applications can build administrator-only workflows on explicit methods:

```python
active = await auth.list_user_sessions(user_id)
removed = await auth.revoke_user_session(user_id, session_id)
removed = await auth.revoke_user_sessions(user_id)
removed = await auth.revoke_user_sessions(
    user_id,
    except_session_id=session_id,
)
```

These methods do not infer an administrator or authorization model. The
calling application must guard them with its own authorization policy.
`revoke_user_session` remains owner-scoped even for administrators so a
mistyped user/session pair cannot revoke a different user's session.

## Upgrade from 0.9.1

Apply the explicit migration before deploying code that reads
`last_active_at`:

```console
python -m hayate_auth generate --dialect sqlite --upgrade-from 0.9.1
python -m hayate_auth generate --dialect postgres --upgrade-from 0.9.1
python -m hayate_auth generate --dialect d1 --upgrade-from 0.9.1
```

The migration backfills existing sessions from `created_at`. Fresh databases
receive a non-null `last_active_at` column directly from the generated schema.
Consequently, an existing session older than the configured inactivity
timeout expires on its next use after the upgrade; deployments should treat
that one-time reauthentication as the secure migration behavior.
