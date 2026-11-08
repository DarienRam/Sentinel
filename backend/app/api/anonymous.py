import secrets

from fastapi import APIRouter, HTTPException, Request, Response

from app.core.anonymous_sessions import (
    check_csrf, cookie_name, issue_cookie, new_session, require_session,
)
from app.core.security_store import AnonymousSession, credential_key

router = APIRouter(prefix="/auth/anonymous-session", tags=["anonymous session"])


@router.post("")
def establish_session(request: Request, response: Response):
    return new_session(request, response)


@router.post("/rotate")
def rotate_session(request: Request, response: Response):
    previous = require_session(request)
    check_csrf(request, previous)
    token = secrets.token_urlsafe(32)
    replacement = AnonymousSession(previous.owner, secrets.token_urlsafe(32), previous.expires_at)
    if not request.app.state.security_store.rotate_session(
        credential_key(request.cookies[cookie_name()]), credential_key(token), replacement
    ):
        raise HTTPException(status_code=401, detail="Anonymous session is missing or expired.")
    issue_cookie(response, token, replacement.expires_at)
    return {"csrf_token": replacement.csrf, "expires_at": replacement.expires_at}


@router.delete("", status_code=204)
def revoke_session(request: Request):
    session = require_session(request)
    check_csrf(request, session)
    request.app.state.security_store.revoke_session(credential_key(request.cookies[cookie_name()]))
    response = Response(status_code=204, headers={"Cache-Control": "no-store"})
    response.delete_cookie(cookie_name(), path="/", httponly=True,
                           secure=cookie_name().startswith("__Host-"), samesite="strict")
    return response
