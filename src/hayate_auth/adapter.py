"""The Adapter protocol (DESIGN §5): minimal model-name + dict CRUD.

Database libraries implement these six methods; everything else in
hayate-auth is written against them. ``Where`` deliberately supports only
the four operators the core actually uses.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal, NamedTuple, Protocol, runtime_checkable


class Where(NamedTuple):
    field: str
    value: Any
    op: Literal["eq", "lt", "gt", "in"] = "eq"


@runtime_checkable
class Adapter(Protocol):
    async def create(self, model: str, data: dict[str, Any]) -> dict[str, Any]: ...

    async def find_one(self, model: str, where: Sequence[Where]) -> dict[str, Any] | None: ...

    async def find_many(
        self,
        model: str,
        where: Sequence[Where],
        *,
        limit: int | None = None,
        sort: tuple[str, str] | None = None,
    ) -> list[dict[str, Any]]: ...

    async def update(
        self, model: str, where: Sequence[Where], data: dict[str, Any]
    ) -> dict[str, Any] | None: ...

    async def update_many(self, model: str, where: Sequence[Where], data: dict[str, Any]) -> int:
        """Atomically update matching rows and return the affected-row count.

        The count is a security boundary for guarded state transitions such
        as ``used = 0 -> 1``. Adapters must execute this as one database
        operation; a read followed by an update is not equivalent.
        """
        ...

    async def delete(self, model: str, where: Sequence[Where]) -> int: ...
