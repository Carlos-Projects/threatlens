"""Optional API key authentication middleware for ThreatLens."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class APIKeyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI, api_key: str = "") -> None:
        super().__init__(app)
        self.api_key = api_key

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        if not self.api_key:
            return await call_next(request)

        if request.url.path.startswith("/static/"):
            return await call_next(request)

        if request.url.path.startswith("/api/"):
            auth = request.headers.get("Authorization", "")
            if auth != f"Bearer {self.api_key}":
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or missing API key"},
                )
        elif request.url.path not in ("/auth",):
            token = request.cookies.get("token") or request.headers.get("X-API-Key", "")
            if token != self.api_key:
                login_form = (
                    "<html><body><h1>Unauthorized</h1>"
                    "<p>Valid API key required.</p>"
                    '<form method="POST" action="/auth">'
                    '<input name="key" placeholder="API Key">'
                    '<button type="submit">Login</button></form></body></html>'
                )
                return HTMLResponse(content=login_form, status_code=401)

        return await call_next(request)
