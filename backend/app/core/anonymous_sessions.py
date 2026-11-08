"""Server-issued anonymous capabilities, never legacy identifier adoption."""
import re
import secrets
import time

from fastapi import HTTPException, Request, Response

from app.core.config import settings
from app.core.security_store import AnonymousSession, credential_key


def cookie_name():
    return "__Host-sentinel_anon" if settings.app_env == "production" else "sentinel_anon"


def check_origin(request: Request):
    if request.headers.get("origin") not in settings.frontend_origins:
        raise HTTPException(status_code=403, detail="Request origin is not allowed.")


def read_session(request: Request):
    token = request.cookies.get(cookie_name(), "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        return None
    return request.app.state.security_store.load_session(credential_key(token))


def require_session(request: Request):
    session = read_session(request)
    if session is None:
        raise HTTPException(status_code=401, detail="Anonymous session is missing or expired.")
    return session


def check_csrf(request: Request, session: AnonymousSession):
    check_origin(request)
    supplied = request.headers.get("x-csrf-token", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", supplied) or not secrets.compare_digest(supplied, session.csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed.")


def get_anonymous_session_id(request: Request) -> str | None:
    # Authenticated account authorization never adopts anonymous ownership.
    from app.core.account_sessions import account_cookie_name
    if request.headers.get("authorization") or request.cookies.get(account_cookie_name()):
        return None
    if request.headers.get("x-anonymous-session"):
        raise HTTPException(status_code=401, detail="Legacy anonymous identifiers are not accepted.")
    session = read_session(request)
    if session is None:
        if request.cookies.get(cookie_name()):
            raise HTTPException(status_code=401, detail="Anonymous session is missing or expired.")
        return None
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        check_csrf(request, session)
    return session.owner


def issue_cookie(response: Response, token: str, expires_at: float):
    response.set_cookie(cookie_name(), token, max_age=max(0, int(expires_at - time.time())),
                        httponly=True, secure=settings.app_env == "production",
                        samesite="strict", path="/")
    response.headers["Cache-Control"] = "no-store"


def new_session(request: Request, response: Response):
    check_origin(request)
    session = read_session(request)
    if session is None:
        token = secrets.token_urlsafe(32)
        session = AnonymousSession("v2:" + secrets.token_urlsafe(24), secrets.token_urlsafe(32),
                                   time.time() + settings.anonymous_session_seconds)
        request.app.state.security_store.put_session(credential_key(token), session)
        issue_cookie(response, token, session.expires_at)
    response.headers["Cache-Control"] = "no-store"
    return {"csrf_token": session.csrf, "expires_at": session.expires_at}
