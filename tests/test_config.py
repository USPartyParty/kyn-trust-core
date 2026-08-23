from pathlib import Path

import pytest
from pydantic import ValidationError

from kyn.config import Settings, read_secret_file
from kyn.main import create_app


def production_settings(tmp_path: Path, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "environment": "production",
        "database_url_file": tmp_path / "database.url",
        "issuer": "https://kyn.usparty.party",
        "signing_seed_file": tmp_path / "signing.seed",
        "pairwise_secret_file": tmp_path / "pairwise.secret",
        "receipt_secret_file": tmp_path / "receipt.secret",
        "bootstrap_token_file": tmp_path / "bootstrap.token",
    }
    values.update(overrides)
    return values


def test_production_rejects_non_https_issuer_and_non_postgres_state(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="production issuer must use https"):
        Settings(**production_settings(tmp_path, issuer="http://kyn.internal"))  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="database URL must come from a secret file"):
        Settings(  # type: ignore[arg-type]
            **production_settings(
                tmp_path,
                database_url_file=None,
                database_url="postgresql+psycopg://x",
            )
        )

    database_url = tmp_path / "database.url"
    database_url.write_text("sqlite+aiosqlite:////tmp/not-production-kyn.db", encoding="utf-8")
    database_url.chmod(0o600)
    settings = Settings(**production_settings(tmp_path))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="requires PostgreSQL"):
        settings.resolved_database_url()


def test_retired_bootstrap_no_longer_requires_token_file(tmp_path: Path) -> None:
    disabled = Settings(  # type: ignore[arg-type]
        **production_settings(
            tmp_path,
            bootstrap_enabled=False,
            bootstrap_token_file=None,
        )
    )
    assert disabled.bootstrap_enabled is False
    assert disabled.bootstrap_token_file is None

    with pytest.raises(ValidationError, match="enabled bootstrap requires a token file"):
        Settings(  # type: ignore[arg-type]
            **production_settings(tmp_path, bootstrap_token_file=None)
        )


def test_secret_reader_rejects_broad_permissions_and_wrong_seed_size(tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.write_bytes(b"s" * 32)
    secret.chmod(0o644)
    with pytest.raises(ValueError, match="permissions are too broad"):
        read_secret_file(secret)

    secret.chmod(0o600)
    with pytest.raises(ValueError, match="exactly 64 raw bytes"):
        read_secret_file(secret, expected_bytes=64)


def test_exact_binary_secret_reader_does_not_strip_seed_bytes(tmp_path: Path) -> None:
    secret = tmp_path / "signing.seed"
    value = b"\n" + b"s" * 30 + b"\t"
    secret.write_bytes(value)
    secret.chmod(0o600)
    assert read_secret_file(secret, expected_bytes=32) == value


def test_production_disables_interactive_and_raw_api_documentation(tmp_path: Path) -> None:
    settings = Settings(**production_settings(tmp_path))  # type: ignore[arg-type]
    app = create_app(settings)
    assert app.docs_url is None
    assert app.redoc_url is None
    assert app.openapi_url is None
