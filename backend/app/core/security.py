from datetime import datetime, timezone
from typing import Any

import bcrypt
import jwt
from jwt import InvalidTokenError

from app.core.config import settings


def hash_password(password: str) -> str:
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > 72:
        raise ValueError("Passwords must be at most 72 UTF-8 bytes.")
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > 72:
        return False
    password_hash_bytes = password_hash.encode("utf-8")
    try:
        return bcrypt.checkpw(password_bytes, password_hash_bytes)
    except ValueError:
        return False


def create_access_token(subject: str, *, jti=None, expires_at=None) -> str:
    import secrets
    now = int(datetime.now(timezone.utc).timestamp())
    expires_at = expires_at or now + settings.access_token_expire_minutes * 60
    payload: dict[str, Any] = {"sub": subject, "exp": expires_at, "iat": now, "nbf": now,
                               "iss": "sentinel", "aud": "sentinel-api", "jti": jti or secrets.token_urlsafe(32)}
    return jwt.encode(payload, settings.secret_key.get_secret_value(), algorithm=settings.algorithm)


def decode_access_claims(token: str) -> dict | None:
    import re
    import time
    if len(token) > 4096:
        return None
    try:
        payload = jwt.decode(token, settings.secret_key.get_secret_value(), algorithms=[settings.algorithm],
                             issuer="sentinel", audience="sentinel-api",
                             options={"require": ["exp", "iat", "nbf", "iss", "aud", "jti", "sub"]})
        subject = payload["sub"]
        if not isinstance(subject, str) or not re.fullmatch(r"[1-9][0-9]{0,18}", subject):
            return None
        if int(subject) > 9223372036854775807:
            return None
        if not isinstance(payload["jti"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", payload["jti"]):
            return None
        if any(type(payload[k]) is not int for k in ("exp", "iat", "nbf")):
            return None
        if not (payload["iat"] <= time.time() and payload["nbf"] >= payload["iat"]
                and payload["iat"] < payload["exp"] <= payload["iat"] + settings.access_token_expire_minutes * 60):
            return None
        return payload
    except (InvalidTokenError, ValueError, TypeError, OverflowError):
        return None


def decode_access_token(token: str) -> str | None:
    claims = decode_access_claims(token)
    return claims["sub"] if claims else None
