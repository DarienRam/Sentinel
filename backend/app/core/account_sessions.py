"""Revocable account JWT sessions; credentials and CSRF values stay out of logs."""
import hashlib
import hmac
import secrets
import time

from fastapi import HTTPException, Request, Response

from app.core.anonymous_sessions import check_csrf
from app.core.config import settings
from app.core.security import create_access_token, decode_access_claims
from app.core.security_store import AccountSession, credential_key


def account_cookie_name():
    return "__Host-sentinel_account" if settings.app_env == "production" else "sentinel_account"


def credential_version(password_hash):
    return hmac.new(settings.secret_key.get_secret_value().encode(),
                    password_hash.encode(), hashlib.sha256).hexdigest()


def issue_account_session(request: Request, user):
    jti = secrets.token_urlsafe(32)
    expires = int(time.time()) + settings.access_token_expire_minutes * 60
    session = AccountSession(user.id, secrets.token_urlsafe(32), credential_version(user.password_hash), expires)
    request.app.state.security_store.put_account_session(credential_key(jti), session)
    return create_access_token(str(user.id), jti=jti, expires_at=expires), session


def resolve_account(request: Request, db, token=None):
    from app.models.user import User

    # Explicit credentials always take precedence; invalid bearer never falls back.
    header = request.headers.get("authorization")
    cookie_auth = not header
    if header:
        parts = header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise unauthorized()
        token = parts[1]
    elif token is None:
        token = request.cookies.get(account_cookie_name())
    if not token:
        return None
    claims = decode_access_claims(token)
    if claims is None:
        raise unauthorized()
    session = request.app.state.security_store.load_account_session(credential_key(claims["jti"]))
    if session is None or str(session.user_id) != claims["sub"] or session.expires_at != claims["exp"]:
        raise unauthorized()
    user = db.get(User, session.user_id)
    if user is None or not hmac.compare_digest(session.credential_version, credential_version(user.password_hash)):
        raise unauthorized()
    if cookie_auth and request.method not in {"GET", "HEAD", "OPTIONS"}:
        check_csrf(request, session)
    request.state.account_session = session
    request.state.account_session_key = credential_key(claims["jti"])
    return user


def set_account_cookie(response: Response, token, session):
    response.set_cookie(account_cookie_name(), token, max_age=max(0, int(session.expires_at-time.time())),
                        httponly=True, secure=settings.app_env == "production", samesite="strict", path="/")
    response.headers["Cache-Control"] = "no-store"


def clear_account_cookie(response: Response):
    response.delete_cookie(account_cookie_name(), path="/", httponly=True,
                           secure=settings.app_env == "production", samesite="strict")
    response.headers["Cache-Control"] = "no-store"


def unauthorized():
    return HTTPException(status_code=401, detail="Invalid or expired authentication token.",
                         headers={"WWW-Authenticate": "Bearer", "Cache-Control": "no-store"})
