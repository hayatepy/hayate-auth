"""Reference Adapter on stdlib sqlite3 (DESIGN §5).

A single shared connection guarded by a lock, with every blocking call pushed
through ``asyncio.to_thread`` (called inline on Pyodide, which has no
threads). Model and field names are validated against ``schema.MODELS``
before they are interpolated, which is what makes the SQL composition safe.
"""

from __future__ import annotations

import asyncio
import sqlite3
import sys
import threading
from collections.abc import Callable, Sequence
from typing import Any

from ..adapter import Where
from ..schema import MODELS, SQLITE_SCHEMA

_OPS = {"eq": "=", "lt": "<", "gt": ">"}


def _validate(model: str, fields: Sequence[str]) -> None:
    columns = MODELS.get(model)
    if columns is None:
        raise ValueError(f"unknown model {model!r}")
    for field in fields:
        if field not in columns:
            raise ValueError(f"unknown field {model}.{field}")


def _where_sql(model: str, where: Sequence[Where]) -> tuple[str, list[Any]]:
    _validate(model, [w.field for w in where])
    if not where:
        return "", []
    clauses: list[str] = []
    params: list[Any] = []
    for w in where:
        if w.op == "in":
            values = list(w.value)
            placeholders = ", ".join("?" * len(values))
            clauses.append(f'"{w.field}" IN ({placeholders})')
            params.extend(values)
        else:
            clauses.append(f'"{w.field}" {_OPS[w.op]} ?')
            params.append(w.value)
    return " WHERE " + " AND ".join(clauses), params


class SQLiteAdapter:
    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._lock = threading.Lock()

    def create_tables(self) -> None:
        """Create the hayate-auth schema. Explicit by design: hayate-auth
        never mutates a database schema behind your back (DESIGN §4)."""
        with self._lock, self._conn:
            self._conn.executescript(SQLITE_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    async def _run[T](self, fn: Callable[[], T]) -> T:
        if sys.platform == "emscripten":  # no threads on Pyodide
            return fn()
        return await asyncio.to_thread(fn)

    async def create(self, model: str, data: dict[str, Any]) -> dict[str, Any]:
        _validate(model, list(data))
        columns = ", ".join(f'"{k}"' for k in data)
        placeholders = ", ".join("?" * len(data))
        sql = f'INSERT INTO "{model}" ({columns}) VALUES ({placeholders})'
        params = list(data.values())

        def run() -> dict[str, Any]:
            with self._lock, self._conn:
                self._conn.execute(sql, params)
            return dict(data)

        return await self._run(run)

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

        def run() -> list[dict[str, Any]]:
            with self._lock:
                rows = self._conn.execute(sql, params).fetchall()
            return [dict(row) for row in rows]

        return await self._run(run)

    async def update(
        self, model: str, where: Sequence[Where], data: dict[str, Any]
    ) -> dict[str, Any] | None:
        await self.update_many(model, where, data)
        return await self.find_one(model, where)

    async def update_many(self, model: str, where: Sequence[Where], data: dict[str, Any]) -> int:
        _validate(model, list(data))
        clause, where_params = _where_sql(model, where)
        assignments = ", ".join(f'"{k}" = ?' for k in data)
        sql = f'UPDATE "{model}" SET {assignments}{clause}'
        params = [*data.values(), *where_params]

        def run() -> int:
            with self._lock, self._conn:
                return self._conn.execute(sql, params).rowcount

        return await self._run(run)

    async def delete(self, model: str, where: Sequence[Where]) -> int:
        clause, params = _where_sql(model, where)
        sql = f'DELETE FROM "{model}"{clause}'

        def run() -> int:
            with self._lock, self._conn:
                return self._conn.execute(sql, params).rowcount

        return await self._run(run)
