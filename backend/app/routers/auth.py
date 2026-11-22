"""Optional password authentication for FirmwareGuard web UI, API, and WebSockets.

When AUTH_PASSWORD is empty (default for local development), all requests pass through.
When AUTH_PASSWORD is set in .env, all /api/v1/* endpoints and WebSocket terminals
require either an HttpOnly signed session cookie (fg_session) or an Authorization
Bearer / X-API-Password header matching AUTH_PASSWORD.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Mapping

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

from app.config import get_settings

SESSION_COOKIE_NAME = "fg_session"
SESSION_TTL_SECONDS = 86400  # 24 hours

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    password: str


def _signing_key(password: str) -> bytes:
    return hashlib.sha256(f"firmwareguard-session:{password}".encode("utf-8")).digest()


def create_session_token(password: str, expires_at: int | None = None) -> str:
    exp = expires_at if expires_at is not None else int(time.time()) + SESSION_TTL_SECONDS
    payload = str(exp)
    sig = hmac.new(_signing_key(password), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify_session_token(token: str, password: str) -> bool:
    if not token or "." not in token:
        return False
    payload, sig = token.split(".", 1)
    try:
        exp = int(payload)
    except ValueError:
        return False
    if exp < int(time.time()):
        return False
    expected = hmac.new(_signing_key(password), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


def is_authenticated(
    cookies: Mapping[str, str],
    headers: Mapping[str, str],
    query_params: Mapping[str, str] | None = None,
) -> bool:
    """Return True if auth is disabled or the request carries valid credentials."""
    password = get_settings().auth_password
    if not password:
        return True

    cookie_token = cookies.get(SESSION_COOKIE_NAME, "")
    if cookie_token and verify_session_token(cookie_token, password):
        return True

    auth_header = headers.get("authorization", "") or headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        candidate = auth_header[7:].strip()
        if hmac.compare_digest(candidate, password) or verify_session_token(candidate, password):
            return True

    header_pw = headers.get("x-api-password", "") or headers.get("X-API-Password", "")
    if header_pw and hmac.compare_digest(header_pw, password):
        return True

    if query_params:
        qp_token = query_params.get("token", "")
        if qp_token and (
            hmac.compare_digest(qp_token, password) or verify_session_token(qp_token, password)
        ):
            return True

    return False


@router.get("/status")
async def auth_status(request: Request):
    """Report whether password authentication is enabled and whether the caller is authenticated."""
    password = get_settings().auth_password
    enabled = bool(password)
    authenticated = is_authenticated(request.cookies, request.headers, request.query_params)
    return {"auth_enabled": enabled, "authenticated": authenticated}


@router.post("/login")
async def login(body: LoginRequest, request: Request, response: Response):
    """Validate AUTH_PASSWORD and issue an HttpOnly session cookie."""
    password = get_settings().auth_password
    if not password:
        return {"auth_enabled": False, "authenticated": True}

    if not hmac.compare_digest(body.password, password):
        raise HTTPException(status_code=401, detail="Invalid password")

    token = create_session_token(password)
    is_https = (
        request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto", "").lower() == "https"
    )
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        secure=is_https,
        path="/",
    )
    return {"auth_enabled": True, "authenticated": True}


@router.post("/logout")
async def logout(response: Response):
    """Clear the authentication session cookie."""
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    return {"authenticated": False}
