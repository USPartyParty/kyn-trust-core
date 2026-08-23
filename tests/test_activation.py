from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

import kyn.activation as activation_module
from kyn.activation import (
    ActivationDraft,
    PreparedActivation,
    activation_body,
    body_digest,
    create_encrypted_key,
    load_encrypted_key,
    prepare_activation,
    submit_prepared_activation,
)
from kyn.models import StoragePosture

NOW = datetime(2030, 1, 1, tzinfo=UTC)


def draft() -> ActivationDraft:
    return ActivationDraft(
        public_label="KC Streich",
        designation_reference="sha256:" + "a" * 64,
        policy_version="1.0.0",
        expires_at=NOW + timedelta(days=365),
        release_version="1.0.0",
        notice_version="1.0.0",
        terms_url="https://usparty.party/kyn/terms/1.0.0",
        privacy_url="https://usparty.party/kyn/privacy/1.0.0",
        operator_contact="security@usparty.party",
        storage_posture=StoragePosture.PROVISIONAL_BETA,
        backup_evidence_reference="sha256:" + "b" * 64,
        sensitive_evidence_enabled=False,
    )


def test_encrypted_activation_key_round_trip_and_public_digest(tmp_path: Path) -> None:
    path = tmp_path / "kc.key.json"
    passphrase = "a-long-test-passphrase-0001"  # noqa: S105
    seed = b"k" * 32
    participant_key = create_encrypted_key(path, passphrase, seed=seed)
    serialized = path.read_text(encoding="utf-8")

    assert seed.hex() not in serialized
    assert path.stat().st_mode & 0o077 == 0
    signer = load_encrypted_key(path, passphrase)
    assert signer.participant_key == participant_key
    body = activation_body(draft(), signer)
    assert body["participant_key"] == participant_key
    assert body_digest(body).startswith("sha256:")


def test_activation_key_rejects_wrong_passphrase_and_replacement(tmp_path: Path) -> None:
    path = tmp_path / "kc.key.json"
    create_encrypted_key(path, "a-long-test-passphrase-0001", seed=b"k" * 32)
    with pytest.raises(InvalidTag):
        load_encrypted_key(path, "a-different-passphrase-0002")
    with pytest.raises(FileExistsError, match="replace"):
        create_encrypted_key(path, "a-long-test-passphrase-0001")


def test_activation_key_refuses_broad_existing_parent(tmp_path: Path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir(mode=0o755)
    parent.chmod(0o755)
    with pytest.raises(ValueError, match="too broad"):
        create_encrypted_key(parent / "kc.key.json", "a-long-test-passphrase-0001")


def test_activation_draft_refuses_sensitive_evidence() -> None:
    payload = json.loads(draft().model_dump_json())
    payload["sensitive_evidence_enabled"] = True
    with pytest.raises(ValueError, match="sensitive evidence"):
        ActivationDraft.model_validate(payload)


def activation_response(prepared: PreparedActivation) -> dict[str, object]:
    body = {key: value for key, value in prepared.request.items() if key != "proof"}
    return {
        "records": [
            {
                "record_type": "subject",
                "subject_id": "sub_example0001",
                "participant_key": body["participant_key"],
            },
            {
                "record_type": "bootstrap_authority",
                "bootstrap_id": "bst_example0001",
                "public_label": body["public_label"],
            },
            {
                "record_type": "authority_grant",
                "authority_grant_id": "agr_example0001",
            },
            {
                "record_type": "operator_release",
                "release_id": "rel_example0001",
                **{
                    key: body[key]
                    for key in (
                        "release_version",
                        "notice_version",
                        "terms_url",
                        "privacy_url",
                        "operator_contact",
                        "storage_posture",
                        "backup_evidence_reference",
                        "sensitive_evidence_enabled",
                    )
                },
            },
        ],
        "receipt": {"record_type": "receipt", "receipt_id": "rcp_example0001"},
        "replayed": False,
    }


def test_two_stage_activation_keeps_secrets_out_of_portable_request_and_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer = load_encrypted_key(
        _key_file(tmp_path),
        "a-long-test-passphrase-0001",
    )
    expected_digest = body_digest(activation_body(draft(), signer))
    prepared = prepare_activation(
        draft=draft(),
        signer=signer,
        confirmation=f"ACTIVATE {expected_digest[-12:]}",
        now=NOW,
    )
    serialized = prepared.model_dump_json()
    assert "passphrase" not in serialized
    assert "bootstrap-token" not in serialized

    bootstrap_token = "bootstrap-token-value-that-is-never-recorded-0000000000000000"  # noqa: S105
    token_path = tmp_path / "bootstrap.token"
    token_path.write_text(bootstrap_token, encoding="utf-8")
    token_path.chmod(0o400)
    evidence_path = tmp_path / "activation.evidence.json"

    def successful_post(api_url: str, token: str, payload: dict[str, object]) -> dict[str, object]:
        assert api_url == "http://127.0.0.1:8090"
        assert token == bootstrap_token
        assert payload == prepared.request
        return activation_response(prepared)

    monkeypatch.setattr(activation_module, "_post_activation", successful_post)
    response = submit_prepared_activation(
        api_url="http://127.0.0.1:8090",
        prepared=prepared,
        bootstrap_token_file=token_path,
        evidence_path=evidence_path,
        confirmation=f"SUBMIT {prepared.activation_body_digest[-12:]}",
        now=NOW,
    )

    assert response["replayed"] is False
    evidence = evidence_path.read_text(encoding="utf-8")
    assert bootstrap_token not in evidence
    assert "a-long-test-passphrase-0001" not in evidence


def _key_file(tmp_path: Path) -> Path:
    path = tmp_path / "kc.key.json"
    create_encrypted_key(path, "a-long-test-passphrase-0001", seed=b"k" * 32)
    return path


def test_submit_rejects_mismatched_release_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer = load_encrypted_key(_key_file(tmp_path), "a-long-test-passphrase-0001")
    expected_digest = body_digest(activation_body(draft(), signer))
    prepared = prepare_activation(
        draft=draft(),
        signer=signer,
        confirmation=f"ACTIVATE {expected_digest[-12:]}",
        now=NOW,
    )
    token_path = tmp_path / "bootstrap.token"
    token_path.write_text("x" * 64, encoding="utf-8")
    token_path.chmod(0o400)
    response = activation_response(prepared)
    records = response["records"]
    assert isinstance(records, list)
    assert isinstance(records[3], dict)
    records[3]["terms_url"] = "https://attacker.invalid/terms"
    monkeypatch.setattr(activation_module, "_post_activation", lambda *_: response)

    with pytest.raises(RuntimeError, match="accepted release"):
        submit_prepared_activation(
            api_url="http://127.0.0.1:8090",
            prepared=prepared,
            bootstrap_token_file=token_path,
            evidence_path=tmp_path / "evidence.json",
            confirmation=f"SUBMIT {prepared.activation_body_digest[-12:]}",
            now=NOW,
        )
