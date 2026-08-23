"""Create-once KYN production secrets without displaying credential values."""

from __future__ import annotations

import argparse
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

MINIMUM_SECRET_BYTES = 32
SIGNING_SEED_BYTES = 32


@dataclass(frozen=True, slots=True)
class Owner:
    uid: int
    gid: int


def _directory(path: Path, owner: Owner) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError(f"secret directory is unsafe: {path}")
    os.chown(path, owner.uid, owner.gid)
    path.chmod(0o700)


def _write_once(path: Path, value: bytes, *, owner: Owner, mode: int) -> bytes:
    _directory(path.parent, owner)
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"secret path is unsafe: {path}")
        existing = path.read_bytes()
        if not existing:
            raise RuntimeError(f"existing secret is empty: {path.name}")
        os.chown(path, owner.uid, owner.gid)
        path.chmod(mode)
        return existing
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)
    os.chown(path, owner.uid, owner.gid)
    path.chmod(mode)
    return value


def provision(
    root: Path,
    *,
    service_owner: Owner,
    postgres_owner: Owner,
    database_host: str,
    state_root: Path | None = None,
) -> tuple[Path, ...]:
    if not database_host or any(character.isspace() for character in database_host):
        raise ValueError("database host is invalid")
    root = root.resolve()
    _directory(root, service_owner)
    if state_root is not None:
        _directory(state_root.resolve() / "database", postgres_owner)
    postgres_password = _write_once(
        root / "postgres/postgres-password",
        secrets.token_hex(32).encode(),
        owner=postgres_owner,
        mode=0o440,
    )
    password = postgres_password.decode("ascii")
    database_url = f"postgresql+psycopg://kyn:{password}@{database_host}:5432/kyn\n".encode()
    database_url_path = root / "service/database-url"
    existing_url = _write_once(
        database_url_path,
        database_url,
        owner=service_owner,
        mode=0o400,
    )
    if existing_url != database_url:
        raise RuntimeError("KYN service database credential conflicts with PostgreSQL")
    signing_seed = root / "service/signing.seed"
    existing_seed = _write_once(
        signing_seed,
        secrets.token_bytes(SIGNING_SEED_BYTES),
        owner=service_owner,
        mode=0o400,
    )
    if len(existing_seed) != SIGNING_SEED_BYTES:
        raise RuntimeError("existing KYN signing seed must be exactly 32 bytes")
    outputs = [database_url_path, signing_seed]
    for name in ("pairwise.secret", "receipt.secret", "bootstrap.token"):
        path = root / f"service/{name}"
        value = _write_once(
            path,
            (secrets.token_urlsafe(48) + "\n").encode(),
            owner=service_owner,
            mode=0o400,
        )
        if len(value.strip()) < MINIMUM_SECRET_BYTES:
            raise RuntimeError(f"existing KYN secret is too short: {name}")
        outputs.append(path)
    return tuple(outputs)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Provision KYN service secrets once without printing values"
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--service-uid", type=int, default=10010)
    parser.add_argument("--service-gid", type=int, default=10010)
    parser.add_argument("--postgres-uid", type=int, default=999)
    parser.add_argument("--postgres-gid", type=int, default=10010)
    parser.add_argument("--database-host", default="kyn-database")
    parser.add_argument("--state-root", type=Path)
    args = parser.parse_args()
    provision(
        args.root,
        service_owner=Owner(args.service_uid, args.service_gid),
        postgres_owner=Owner(args.postgres_uid, args.postgres_gid),
        database_host=args.database_host,
        state_root=args.state_root,
    )
    print("KYN secret files created or verified without displaying credential values.")


if __name__ == "__main__":
    main()
