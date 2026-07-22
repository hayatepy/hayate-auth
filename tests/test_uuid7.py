"""The UUIDv7 primary keys: version, variant, and coarse time ordering."""

import time
import uuid

from hayate_auth._uuid7 import new_id, uuid7


def test_version_and_variant():
    value = uuid7()
    assert value.version == 7
    assert value.variant == uuid.RFC_4122


def test_time_ordering_across_milliseconds():
    first = new_id()
    time.sleep(0.002)
    second = new_id()
    assert first < second


def test_new_id_is_canonical_text():
    text = new_id()
    assert uuid.UUID(text) and len(text) == 36
