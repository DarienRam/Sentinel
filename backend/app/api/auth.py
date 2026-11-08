from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.account_sessions import (
    clear_account_cookie, issue_account_session, resolve_account, set_account_cookie, unauthorized,
)
from app.core.anonymous_sessions import check_origin
from app.core.database import get_db
from app.core.resource_protection import check_login_budget
from app.core.security import (
    hash_password,
    verify_password,
)
from app.models.user import User
from app.schemas.auth import AuthToken, CookieAuthSession, PasswordChange, UserLogin, UserPublic, UserRegister


router = APIRouter(prefix="/auth", tags=["auth"])
@router.post(
    "/register",
    response_model=UserPublic,
    status_code=status.HTTP_201_CREATED,
)
def register_user(payload: UserRegister, db: Session = Depends(get_db)) -> UserPublic:
    existing_user = db.scalar(
        select(User).where(
            or_(
                User.username == payload.username,
                User.email == payload.email,
            )
        )
    )

    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email is already registered.",
        )

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        # The unique constraints decide concurrent registrations, not the precheck.
        db.rollback()
        raise HTTPException(status_code=409, detail="Username or email is already registered.") from None
    db.refresh(user)

    return _user_to_schema(user)


@router.post("/login", response_model=AuthToken | CookieAuthSession)
def login_user(payload: UserLogin, request: Request, response: Response,
               transport: Literal["bearer", "cookie"] = "bearer", db: Session = Depends(get_db)):
    check_login_budget(request, payload.login)
    if transport == "cookie":
        check_origin(request)  # Prevent login CSRF/session substitution.
    user = db.scalar(select(User).where(or_(User.username == payload.login, User.email == payload.login)))
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid login credentials.")
    token, session = issue_account_session(request, user)
    response.headers["Cache-Control"] = "no-store"
    if transport == "cookie":
        set_account_cookie(response, token, session)
        return CookieAuthSession(user=_user_to_schema(user), csrf_token=session.csrf, expires_at=session.expires_at)
    return AuthToken(access_token=token, user=_user_to_schema(user))


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = resolve_account(request, db)
    if user is None:
        raise unauthorized()
    return user


def get_optional_current_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    return resolve_account(request, db)


@router.get("/session", response_model=CookieAuthSession)
def restore_account_session(request: Request, response: Response, user: User = Depends(get_current_user)):
    # CSRF disclosure is restricted even for same-site sibling origins.
    check_origin(request)
    response.headers["Cache-Control"] = "no-store"
    session = request.state.account_session
    return CookieAuthSession(user=_user_to_schema(user), csrf_token=session.csrf, expires_at=session.expires_at)


@router.post("/logout", status_code=204)
def logout(request: Request, user: User = Depends(get_current_user)):
    request.app.state.security_store.revoke_account_session(request.state.account_session_key)
    response = Response(status_code=204)
    clear_account_cookie(response)
    return response


@router.post("/password", status_code=204)
def change_password(payload: PasswordChange, request: Request,
                    user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    check_login_budget(request, user.username)
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid login credentials.")
    old_hash = user.password_hash
    result = db.execute(update(User).where(User.id == user.id, User.password_hash == old_hash)
                        .values(password_hash=hash_password(payload.new_password)))
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="Credentials changed; authenticate again.")
    db.commit()
    # Every session checks the persisted hash fingerprint, so all old sessions fail
    # even if a concurrent login issued a token just before this commit.
    request.app.state.security_store.revoke_account_session(request.state.account_session_key)
    response = Response(status_code=204)
    clear_account_cookie(response)
    return response


@router.get("/me", response_model=UserPublic)
def get_current_user_profile(
    user: User = Depends(get_current_user),
) -> UserPublic:
    return _user_to_schema(user)


def _user_to_schema(user: User) -> UserPublic:
    return UserPublic(
        id=user.id,
        username=user.username,
        email=user.email,
        created_at=user.created_at,
    )
