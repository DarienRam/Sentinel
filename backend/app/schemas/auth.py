from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, EmailStr, Field, field_validator


Username = Annotated[
    str,
    Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$"),
]
def validate_password_bytes(value: str) -> str:
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise ValueError("Password must contain valid Unicode characters.") from None
    if size > 72:
        raise ValueError("Password must be at most 72 UTF-8 bytes; it will not be truncated.")
    return value


Password = Annotated[
    str, Field(min_length=8, max_length=128), AfterValidator(validate_password_bytes)
]


class UserRegister(BaseModel):
    username: Username
    email: EmailStr = Field(..., min_length=5, max_length=255)
    password: Password

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if "@" not in normalized or "." not in normalized.split("@")[-1]:
            raise ValueError("Enter a valid email address.")
        return normalized


class UserLogin(BaseModel):
    login: str = Field(..., min_length=3, max_length=255)
    password: Password

    @field_validator("login")
    @classmethod
    def normalize_login(cls, value: str) -> str:
        return value.strip().lower()


class UserPublic(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime


class AuthToken(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic


class CookieAuthSession(BaseModel):
    token_type: str = "cookie"
    user: UserPublic
    csrf_token: str
    expires_at: float


class PasswordChange(BaseModel):
    current_password: Password
    new_password: Password
