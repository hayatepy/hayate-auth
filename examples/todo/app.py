"""A login-protected TODO app — the v0.1 acceptance target.

The same file runs under uvicorn (``uv run uvicorn app:app``) and on
Cloudflare Python Workers (see entry.py); storage is per-user in memory,
auth state lives in SQLite through the reference adapter.
"""

import os

from hayate import Context, Hayate, HTTPException

from hayate_auth import Auth
from hayate_auth.adapters.sqlite import SQLiteAdapter

adapter = SQLiteAdapter(os.environ.get("TODO_DB", ":memory:"))
adapter.create_tables()

auth = Auth(
    secret=os.environ.get("AUTH_SECRET", "dev-secret-change-me"),
    adapter=adapter,
)

app = Hayate()
auth.register(app)

TODOS: dict[str, list[dict]] = {}
_serial = 0


def _next_id() -> str:
    global _serial
    _serial += 1
    return str(_serial)


@app.get("/todos", auth.require_session())
async def list_todos(c: Context):
    return c.json(TODOS.get(c.get("user")["id"], []))


@app.post("/todos", auth.require_session())
async def create_todo(c: Context):
    data = await c.req.json()
    if not isinstance(data, dict) or not isinstance(data.get("title"), str):
        raise HTTPException(400, title="Body must be a JSON object with a string 'title'")
    todo = {"id": _next_id(), "title": data["title"], "done": False}
    TODOS.setdefault(c.get("user")["id"], []).append(todo)
    return c.json(todo, status=201)


@app.delete("/todos/:id", auth.require_session())
async def delete_todo(c: Context):
    todos = TODOS.get(c.get("user")["id"], [])
    for i, todo in enumerate(todos):
        if todo["id"] == c.req.param("id"):
            del todos[i]
            return c.body(None, status=204)
    raise HTTPException(404, title="Todo not found")
