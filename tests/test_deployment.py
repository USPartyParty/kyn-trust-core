import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy" / "compose.production.yml"
BACKUP_RUNNER = ROOT / "deploy" / "kyn-backup-run"
RESTORE_RUNNER = ROOT / "deploy" / "kyn-restore-test"
RESTORE_WRAPPER = ROOT / "deploy" / "kyn-restore-run"
RESTORE_LATEST = ROOT / "deploy" / "kyn-restore-latest"
ROTATION_RUNNER = ROOT / "deploy" / "kyn-rotate-preactivation"
PI_PROVISIONER = ROOT / "deploy" / "provision-pi-backup-repository.sh"
BACKUP_INSTALLER = ROOT / "deploy" / "install-kyn-backup.sh"


def test_api_is_loopback_published_while_database_network_stays_internal() -> None:
    source = COMPOSE.read_text(encoding="utf-8")
    assert '"${KYN_PUBLISH_ADDRESS:-127.0.0.1}:${KYN_LOOPBACK_PORT:-8090}:8090"' in source
    networks = source.rsplit("\nnetworks:\n", maxsplit=1)[1]
    api_network, data_network = networks.split("  kyn_data:\n", maxsplit=1)
    assert "  kyn_api:\n    driver: bridge" in api_network
    assert "internal: true" not in api_network
    assert "    internal: true" in data_network
    database = source.split("  kyn-database:\n", maxsplit=1)[1].split(
        "  kyn-migrate:\n", maxsplit=1
    )[0]
    assert "ports:" not in database


def test_backup_shell_contracts_are_syntax_valid() -> None:
    for script in (
        BACKUP_RUNNER,
        RESTORE_RUNNER,
        RESTORE_WRAPPER,
        RESTORE_LATEST,
        ROTATION_RUNNER,
        PI_PROVISIONER,
        BACKUP_INSTALLER,
    ):
        subprocess.run(  # noqa: S603 - fixed reviewed repository scripts
            ["/usr/bin/bash", "-n", str(script)],
            check=True,
        )


def test_kyn_backup_is_encrypted_separate_and_restore_tested() -> None:
    backup = BACKUP_RUNNER.read_text(encoding="utf-8")
    restore = RESTORE_RUNNER.read_text(encoding="utf-8")
    pi = PI_PROVISIONER.read_text(encoding="utf-8")

    assert 'repository_scope: "fla_kyn_only"' in backup
    assert 'excluded_organizations: ["campaign_committee"]' in backup
    assert "--tag kyn --tag fla --tag gate-b" in backup
    assert "kyn-service-secrets.tar" in backup
    assert "org.opencontainers.image.revision" in backup
    assert "--network none" in restore
    assert "69573b32242ca232f65871d4cb916ba7210a372b9bd74068204c1a9a57bada4f" in restore
    assert 'fail "run as root"' not in restore
    assert "source_database_untouched: true" in restore
    assert 'database_restore: "passed"' in restore
    assert "Match User kyn-backup" in pi
    assert "ChrootDirectory /srv/kyn-backup" in pi
    assert "ForceCommand internal-sftp" in pi
    installer = BACKUP_INSTALLER.read_text(encoding="utf-8")
    assert "kyn-restore-run" in installer
    assert "/etc/kyn-backup" in installer
    assert "NOPASSWD" in installer
    assert "kyn-restore-latest" in installer
    rotation = ROTATION_RUNNER.read_text(encoding="utf-8")
    assert "operator release is not dark" in rotation
    assert '[[ "${counts}" == "0|0" ]]' in rotation
    assert "rotation-rollback" in rotation
    assert "all_service_credentials_rotated: true" in rotation
    assert "kyn-rotate-preactivation" in installer
