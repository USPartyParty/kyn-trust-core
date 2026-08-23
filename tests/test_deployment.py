from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy" / "compose.production.yml"


def test_api_is_loopback_published_while_database_network_stays_internal() -> None:
    source = COMPOSE.read_text(encoding="utf-8")
    assert '"127.0.0.1:${KYN_LOOPBACK_PORT:-8090}:8090"' in source
    networks = source.rsplit("\nnetworks:\n", maxsplit=1)[1]
    api_network, data_network = networks.split("  kyn_data:\n", maxsplit=1)
    assert "  kyn_api:\n    driver: bridge" in api_network
    assert "internal: true" not in api_network
    assert "    internal: true" in data_network
    database = source.split("  kyn-database:\n", maxsplit=1)[1].split(
        "  kyn-migrate:\n", maxsplit=1
    )[0]
    assert "ports:" not in database
