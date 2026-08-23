from __future__ import annotations

import os
from pathlib import Path

import pytest

from kyn.provision import Owner, provision


def test_secret_provisioning_is_create_once_and_never_replaces_values(tmp_path: Path) -> None:
    owner = Owner(os.getuid(), os.getgid())
    root = tmp_path / "secrets"
    first = provision(
        root,
        service_owner=owner,
        postgres_owner=owner,
        database_host="kyn-database",
    )
    values = {path: path.read_bytes() for path in first}
    second = provision(
        root,
        service_owner=owner,
        postgres_owner=owner,
        database_host="kyn-database",
    )

    assert first == second
    assert {path: path.read_bytes() for path in second} == values
    assert len((root / "service/signing.seed").read_bytes()) == 32
    assert all(path.stat().st_mode & 0o077 == 0 for path in first if "service" in path.parts)


def test_secret_provisioning_rejects_conflicting_existing_database_url(
    tmp_path: Path,
) -> None:
    owner = Owner(os.getuid(), os.getgid())
    root = tmp_path / "secrets"
    provision(root, service_owner=owner, postgres_owner=owner, database_host="first")

    with pytest.raises(RuntimeError, match="conflicts"):
        provision(root, service_owner=owner, postgres_owner=owner, database_host="second")
