"""Fail-closed standalone KYN runtime configuration."""

from functools import lru_cache
from pathlib import Path
from typing import Literal, Self

from pydantic import AnyHttpUrl, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MINIMUM_SECRET_BYTES = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KYN_", extra="forbid")

    environment: Literal["development", "integration", "production"] = "development"
    database_url: str | None = None
    database_url_file: Path | None = None
    issuer: AnyHttpUrl
    policy_profile: str = "kyn-000c-public-beta-v1"
    bootstrap_public_label: str = "KC Streich"
    signing_key_id: str = "kyn-beta-presentation-1"
    signing_seed_file: Path
    pairwise_secret_file: Path
    receipt_secret_file: Path
    bootstrap_enabled: bool = True
    bootstrap_token_file: Path | None = None
    action_clock_skew_seconds: int = Field(default=120, ge=15, le=300)
    bind_host: str = "127.0.0.1"
    bind_port: int = Field(default=8090, ge=1024, le=65535)
    forwarded_allow_ips: str = "127.0.0.1"

    @model_validator(mode="after")
    def production_requires_https_and_postgres(self) -> Self:
        if (self.database_url is None) == (self.database_url_file is None):
            raise ValueError("configure exactly one database URL source")
        if self.environment == "production":
            if self.issuer.scheme != "https":
                raise ValueError("production issuer must use https")
            if self.database_url_file is None:
                raise ValueError("production database URL must come from a secret file")
            if self.bind_host not in {"127.0.0.1", "0.0.0.0"}:  # noqa: S104
                raise ValueError("production bind host must be explicit")
        if self.bootstrap_enabled and self.bootstrap_token_file is None:
            raise ValueError("enabled bootstrap requires a token file")
        return self

    def resolved_database_url(self) -> str:
        value = self.database_url
        if self.database_url_file is not None:
            value = read_secret_file(self.database_url_file).decode("utf-8")
        if value is None:
            raise ValueError("database URL is unavailable")
        if self.environment == "production" and not value.startswith("postgresql+psycopg://"):
            raise ValueError("production KYN state requires PostgreSQL through psycopg")
        return value


def read_secret_file(path: Path, *, expected_bytes: int | None = None) -> bytes:
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"secret path is not a regular file: {resolved}")
    if resolved.stat().st_mode & 0o077:
        raise ValueError(f"secret file permissions are too broad: {resolved}")
    raw = resolved.read_bytes()
    value = raw if expected_bytes is not None else raw.strip()
    if expected_bytes is not None and len(value) != expected_bytes:
        raise ValueError(f"secret file must contain exactly {expected_bytes} raw bytes")
    if expected_bytes is None and len(value) < MINIMUM_SECRET_BYTES:
        raise ValueError("secret file must contain at least 32 bytes")
    return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
