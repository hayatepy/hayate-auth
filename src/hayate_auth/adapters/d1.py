"""Cloudflare D1 Adapter (DESIGN §5): the same SQL surface as the sqlite
reference, executed through the Workers D1 binding's prepare/bind API.

Production measurement (docs/research/kdf.md, finding 5) showed in-memory
state does not survive isolate boundaries — D1 is the durable path on
Workers. Guarded imports keep this importable everywhere; instantiation
requires the JS binding (``env.DB``).

Schema application stays explicit: pipe ``python -m hayate_auth generate
--dialect d1`` into ``wrangler d1 execute`` (never applied automatically).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ..adapter import Where
from .sqlite import _validate, _where_sql


def _to_rows(result: Any) -> list[dict[str, Any]]:
    rows = getattr(result, "results", None)
    if rows is None:
        return []
    return [dict(row.to_py()) if hasattr(row, "to_py") else dict(row) for row in rows]


def _changes(result: Any) -> int:
    meta = getattr(result, "meta", None)
    if meta is not None and hasattr(meta, "to_py"):
        meta = meta.to_py()
    if isinstance(meta, dict):
        changes = meta.get("changes")
    else:
        changes = getattr(meta, "changes", None) if meta is not None else None
    return int(changes) if changes is not None else 0


class D1Adapter:
    def __init__(self, database: Any) -> None:
        self._db = database

    async def _all(self, sql: str, params: Sequence[Any]) -> Any:
        statement = self._db.prepare(sql)
        if params:
            statement = statement.bind(*params)
        return await statement.all()

    async def create(self, model: str, data: dict[str, Any]) -> dict[str, Any]:
        _validate(model, list(data))
        columns = ", ".join(f'"{k}"' for k in data)
        placeholders = ", ".join("?" * len(data))
        await self._all(
            f'INSERT INTO "{model}" ({columns}) VALUES ({placeholders})', list(data.values())
        )
        return dict(data)

    async def find_one(self, model: str, where: Sequence[Where]) -> dict[str, Any] | None:
        rows = await self.find_many(model, where, limit=1)
        return rows[0] if rows else None

    async def find_many(
        self,
        model: str,
        where: Sequence[Where],
        *,
        limit: int | None = None,
        sort: tuple[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        _validate(model, ())
        clause, params = _where_sql(model, where)
        sql = f'SELECT * FROM "{model}"{clause}'
        if sort is not None:
            field, direction = sort
            _validate(model, [field])
            if direction.lower() not in ("asc", "desc"):
                raise ValueError(f"sort direction must be asc or desc, got {direction!r}")
            sql += f' ORDER BY "{field}" {direction.upper()}'
        if limit is not None:
            sql += " LIMIT ?"
            params = [*params, int(limit)]
        return _to_rows(await self._all(sql, params))

    async def update(
        self, model: str, where: Sequence[Where], data: dict[str, Any]
    ) -> dict[str, Any] | None:
        await self.update_many(model, where, data)
        return await self.find_one(model, where)

    async def update_many(self, model: str, where: Sequence[Where], data: dict[str, Any]) -> int:
        _validate(model, list(data))
        clause, where_params = _where_sql(model, where)
        assignments = ", ".join(f'"{k}" = ?' for k in data)
        result = await self._all(
            f'UPDATE "{model}" SET {assignments}{clause}', [*data.values(), *where_params]
        )
        return _changes(result)

    async def delete(self, model: str, where: Sequence[Where]) -> int:
        clause, params = _where_sql(model, where)
        result = await self._all(f'DELETE FROM "{model}"{clause}', params)
        return _changes(result)
