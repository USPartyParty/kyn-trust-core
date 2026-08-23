"""Digest-pinned, explicit PostgreSQL schema migration runner."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

import psycopg

from kyn.config import get_settings


def _psycopg_url(database_url: str) -> str:
    return database_url.replace("postgresql+psycopg://", "postgresql://", 1)


def migrate(directory: Path) -> tuple[str, ...]:
    settings = get_settings()
    migration_paths = tuple(sorted(directory.glob("[0-9][0-9][0-9][0-9]_*.sql")))
    if not migration_paths:
        raise RuntimeError("no KYN migrations were found")
    applied: list[str] = []
    with psycopg.connect(_psycopg_url(settings.resolved_database_url())) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS kyn_schema_migrations (
                version VARCHAR(200) PRIMARY KEY,
                sha256 VARCHAR(71) NOT NULL CHECK (sha256 ~ '^sha256:[0-9a-f]{64}$'),
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        for path in migration_paths:
            sql = path.read_text(encoding="utf-8")
            digest = f"sha256:{hashlib.sha256(sql.encode()).hexdigest()}"
            existing = connection.execute(
                "SELECT sha256 FROM kyn_schema_migrations WHERE version = %s",
                (path.name,),
            ).fetchone()
            if existing is not None:
                if existing[0] != digest:
                    raise RuntimeError(f"applied KYN migration digest changed: {path.name}")
                continue
            connection.execute(sql)
            connection.execute(
                "INSERT INTO kyn_schema_migrations (version, sha256) VALUES (%s, %s)",
                (path.name, digest),
            )
            applied.append(path.name)
    return tuple(applied)


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply digest-pinned KYN migrations")
    parser.add_argument("--directory", type=Path, default=Path("/app/migrations"))
    args = parser.parse_args()
    applied = migrate(args.directory)
    print(f"KYN schema verified; {len(applied)} migration(s) applied.")


if __name__ == "__main__":
    main()
