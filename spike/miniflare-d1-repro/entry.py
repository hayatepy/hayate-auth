"""Minimal Python Worker + D1 probe for workers-sdk#14848."""

from urllib.parse import urlsplit

from workers import Response, WorkerEntrypoint


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        path = urlsplit(request.url).path
        if path == "/health":
            return Response("ok")
        if path == "/write":
            await (
                self.env.DB.prepare(
                    "INSERT INTO probe (id, value) VALUES (?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET value = excluded.value"
                )
                .bind(1, "written")
                .all()
            )
            return Response("written")
        if path == "/read":
            await self.env.DB.prepare("SELECT value FROM probe WHERE id = ?").bind(1).all()
            return Response("read")
        return Response("Not Found", status=404)
