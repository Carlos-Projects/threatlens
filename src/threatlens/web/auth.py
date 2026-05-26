"""Optional API key authentication middleware for ThreatLens.

Supports constant-time comparison, rate limiting, and secure cookies.
"""

from __future__ import annotations

import secrets as _secrets
import time
from collections import defaultdict
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Middleware that optionally authenticates requests with an API key.

    Features:
    - Constant-time key comparison (prevents timing attacks)
    - Per-IP rate limiting on auth attempts
    - Secure cookie-based session tokens
    - Bypass for static files
    """

    def __init__(self, app: FastAPI, api_key: str = "") -> None:
        super().__init__(app)
        self.api_key = api_key
        self._auth_attempts: dict[str, list[float]] = defaultdict(list)

    def _rate_limited(self, ip: str) -> bool:
        now = time.time()
        window = 60.0
        max_attempts = 10

        self._auth_attempts[ip] = [t for t in self._auth_attempts[ip] if now - t < window]

        if len(self._auth_attempts[ip]) >= max_attempts:
            return True

        self._auth_attempts[ip].append(now)
        return False

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        if not self.api_key:
            return await call_next(request)

        if request.url.path.startswith("/static/"):
            return await call_next(request)

        if request.url.path.startswith("/api/"):
            auth = request.headers.get("Authorization", "")
            expected = f"Bearer {self.api_key}"
            if not _secrets.compare_digest(auth, expected):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or missing API key"},
                )
            return await call_next(request)

        if request.url.path == "/auth" and request.method == "POST":
            client_ip = request.client.host if request.client else "unknown"
            if self._rate_limited(client_ip):
                return HTMLResponse(
                    content="<html><body><h1>429 Too Many Requests</h1></body></html>",
                    status_code=429,
                )

            form = await request.form()
            key = str(form.get("key", ""))
            if _secrets.compare_digest(key, self.api_key):
                response = RedirectResponse(url="/", status_code=302)
                response.set_cookie(
                    key="token",
                    value=self.api_key,
                    httponly=True,
                    samesite="lax",
                    max_age=3600,
                )
                return response
            return HTMLResponse(
                content="<html><body><h1>Invalid key</h1></body></html>",
                status_code=401,
            )

        if request.url.path not in ("/auth",):
            token = request.cookies.get("token") or request.headers.get("X-API-Key", "")
            if not _secrets.compare_digest(token, self.api_key):
                login_form = (
                    "<html><body><h1>Unauthorized</h1>"
                    "<p>Valid API key required.</p>"
                    '<form method="POST" action="/auth">'
                    '<input name="key" placeholder="API Key">'
                    '<button type="submit">Login</button></form></body></html>'
                )
                return HTMLResponse(content=login_form, status_code=401)

        return await call_next(request)
