"""UUIDv7 (RFC 9562): time-ordered primary keys for every model.

Python 3.14 ships ``uuid.uuid7``; on 3.12/3.13 this falls back to a compliant
implementation (48-bit Unix milliseconds + 74 random bits). Within the same
millisecond the fallback gives no ordering guarantee, which is fine for
primary keys — the point is coarse time-sortability, not a sequence.
"""

from __future__ import annotations

import os
import time
import uuid

if hasattr(uuid, "uuid7"):  # Python 3.14+
    uuid7 = uuid.uuid7
else:

    def uuid7() -> uuid.UUID:
        ts_ms = time.time_ns() // 1_000_000
        rand = int.from_bytes(os.urandom(10), "big")
        value = (
            (ts_ms & 0xFFFF_FFFF_FFFF) << 80
            | 0x7 << 76
            | ((rand >> 62) & 0xFFF) << 64
            | 0b10 << 62
            | (rand & 0x3FFF_FFFF_FFFF_FFFF)
        )
        return uuid.UUID(int=value)


def new_id() -> str:
    """A fresh UUIDv7 in the canonical text form used as primary key."""
    return str(uuid7())
