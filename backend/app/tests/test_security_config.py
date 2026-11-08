import os
from pathlib import Path
import subprocess
import sys

import pytest
from pydantic import ValidationError

from app.core.config import Settings


@pytest.fixture(autouse=True)
def isolated_settings_environment(monkeypatch):
    # Settings tests use synthetic inputs and never load the user's .env.
    for name in Settings.model_fields:
        monkeypatch.delenv(name.upper(), raising=False)
        monkeypatch.delenv(name, raising=False)


def test_development_and_test_allow_existing_local_defaults():
    for environment in ("development", "test"):
        assert Settings(_env_file=None, app_env=environment).app_env == environment


@pytest.mark.parametrize("key", [None, "", "short", "change-this-in-development", "x" * 64,
                                      "abcd1234" * 8, "replace-me-with-a-long-example-key",
                                      " 8rK2vD9!aZ5#tP7xQ1mW4sJ6nL3hF0cB "])
def test_production_rejects_missing_or_unsafe_secret(key):
    values = {} if key is None else {"secret_key": key}
    with pytest.raises(ValidationError, match="Production requires"):
        Settings(_env_file=None, app_env="production", **values)


@pytest.mark.parametrize("algorithm,minimum", [("HS256", 32), ("HS384", 48), ("HS512", 64)])
def test_production_key_lengths_and_no_secret_in_repr(algorithm, minimum):
    key = "7xQ!9mZ2aK#6rT4vB8nW3pD5sJ0hF1cLuEoRiYgUqAzXwVtSNePbHkdCfM4jR8zY2uT6iO0"
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="production", algorithm=algorithm, secret_key=key[:minimum - 1])
    settings = Settings(_env_file=None, app_env="production", algorithm=algorithm, secret_key=key[:minimum])
    assert key[:minimum] not in repr(settings)
    assert settings.secret_key.get_secret_value() == key[:minimum]


def test_production_validation_error_does_not_print_supplied_key():
    key = "synthetic-secret-for-error-test"
    with pytest.raises(ValidationError) as error:
        Settings(_env_file=None, app_env="production", secret_key=key)
    assert key not in str(error.value)


@pytest.mark.parametrize("environment", ["prod", "staging", "", "Production"])
def test_unknown_environment_fails_instead_of_bypassing_production_checks(environment):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env=environment)


@pytest.mark.parametrize("algorithm", ["none", "RS256"])
def test_production_rejects_unsupported_algorithm(algorithm):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="production", algorithm=algorithm,
                 secret_key="8rK2vD9!aZ5#tP7xQ1mW4sJ6nL3hF0cB")


def test_production_environment_import_fails_closed_without_secret(tmp_path):
    backend = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "-c", "from app.core.config import settings"],
        cwd=tmp_path,
        env={"PATH": os.defpath, "PYTHONPATH": str(backend), "APP_ENV": "production",
             "DATABASE_URL": "sqlite:///:memory:", "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True, text=True, check=False,
    )
    assert result.returncode != 0
    assert "Production requires" in result.stderr


def test_explicit_production_environment_secret(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SECRET_KEY", "8rK2vD9!aZ5#tP7xQ1mW4sJ6nL3hF0cB")
    assert Settings(_env_file=None).app_env == "production"


@pytest.mark.parametrize("algorithm", ["HS256", "HS384", "HS512"])
def test_production_signing_preserves_configured_key_and_roundtrip(monkeypatch, algorithm):
    from app.core import security
    import jwt

    key = "7xQ!9mZ2aK#6rT4vB8nW3pD5sJ0hF1cLuEoRiYgUqAzXwVtSNePbHkdCfM4jR8zY2uT6iO0"
    configured = Settings(_env_file=None, app_env="production", algorithm=algorithm, secret_key=key)
    monkeypatch.setattr(security, "settings", configured)
    token = security.create_access_token("42")
    assert jwt.decode(token, key, algorithms=[algorithm], audience="sentinel-api", issuer="sentinel")["sub"] == "42"
    assert security.decode_access_token(token) == "42"
    assert configured.secret_key.get_secret_value() == key
