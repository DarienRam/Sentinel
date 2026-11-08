import os
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Sentinel"
    app_env: Literal["development", "test", "production"] = "development"
    # SQLite keeps the public local setup self-contained. Deployments can set
    # DATABASE_URL to a managed PostgreSQL connection instead.
    database_url: str = "sqlite:///./sentinel.db"
    secret_key: SecretStr = SecretStr("change-this-in-development")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = Field(default=60, ge=1, le=1440)
    frontend_origins: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]
    security_backend: Literal["memory", "redis"] = "memory"
    redis_url: SecretStr | None = None
    anonymous_session_seconds: int = Field(default=604800, ge=60, le=2592000)
    max_request_body_bytes: int = Field(default=65536, ge=1024, le=1048576)
    request_body_timeout_seconds: float = Field(default=5, gt=0, le=30)
    max_inflight_requests: int = Field(default=8, ge=1, le=64)
    history_default_limit: int = Field(default=100, ge=1, le=100)

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", hide_input_in_errors=True
    )

    @model_validator(mode="after")
    def require_production_signing_key(self) -> "Settings":
        if self.app_env != "production":
            return self

        # RFC 7518: HMAC keys must be at least as long as the hash output.
        required_bytes = {"HS256": 32, "HS384": 48, "HS512": 64}.get(self.algorithm)
        key = self.secret_key.get_secret_value()
        placeholder = any(
            marker in key.casefold()
            for marker in ("change-this", "changeme", "change-me", "your-secret", "replace-me", "example")
        )
        repeated = any(
            len(key) % width == 0 and key == key[:width] * (len(key) // width)
            for width in range(1, len(key) // 2 + 1)
        )
        if (
            required_bytes is None
            or "secret_key" not in self.model_fields_set
            or len(key.encode("utf-8")) < required_bytes
            or len(set(key)) < 8
            or repeated
            or key != key.strip()
            or placeholder
        ):
            raise ValueError(
                "Production requires an explicit random SECRET_KEY of at least "
                "32/48/64 UTF-8 bytes for HS256/HS384/HS512; placeholders, "
                "low-diversity keys and surrounding whitespace are not allowed."
            )
        return self


# Test startup must not load the developer's environment file or infrastructure.
settings = Settings(_env_file=None) if os.environ.get("APP_ENV") == "test" else Settings()
