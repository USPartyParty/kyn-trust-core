from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from kyn.config import Settings
from kyn.crypto import Ed25519Signer
from kyn.database import create_database_engine
from kyn.main import create_app
from kyn.persistence import Base


def write_secret(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    path.chmod(0o600)
    return path


def signed_payload(
    signer: Ed25519Signer,
    *,
    operation: str,
    nonce: str,
    body: dict[str, object],
    now: datetime,
) -> dict[str, object]:
    issued_at = now.isoformat().replace("+00:00", "Z")
    signature = signer.sign_action(
        operation=operation,
        nonce=nonce,
        issued_at=issued_at,
        body=body,  # type: ignore[arg-type]
    )
    return {
        **body,
        "proof": {
            "nonce": nonce,
            "issued_at": issued_at,
            "signature": signature,
        },
    }


def prepare_database(database_url: str) -> None:
    async def prepare() -> None:
        engine = create_database_engine(database_url)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        await engine.dispose()

    asyncio.run(prepare())


def test_retired_bootstrap_endpoint_is_absent(tmp_path: Path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'retired.db'}"
    prepare_database(database_url)
    settings = Settings(
        environment="integration",
        database_url=database_url,
        issuer="https://kyn.usparty.party",
        signing_seed_file=write_secret(tmp_path / "signing.seed", b"s" * 32),
        pairwise_secret_file=write_secret(tmp_path / "pairwise.secret", b"p" * 32),
        receipt_secret_file=write_secret(tmp_path / "receipt.secret", b"r" * 32),
        bootstrap_enabled=False,
        bootstrap_token_file=None,
    )
    participant = Ed25519Signer.from_seed("retired-bootstrap", b"k" * 32)
    now = datetime.now(tz=UTC).replace(microsecond=0)
    body = {
        "participant_key": participant.participant_key,
        "public_label": "KC Streich",
        "designation_reference": "sha256:" + "a" * 64,
        "policy_version": "1.0.0",
        "expires_at": (now + timedelta(days=365)).isoformat().replace("+00:00", "Z"),
        "release_version": "1.0.0",
        "notice_version": "1.0.0",
        "terms_url": "https://usparty.party/kyn/terms/1.0.0",
        "privacy_url": "https://usparty.party/kyn/privacy/1.0.0",
        "operator_contact": "kc@uspartyparty.com",
        "storage_posture": "provisional_beta",
        "backup_evidence_reference": "sha256:" + "b" * 64,
        "sensitive_evidence_enabled": False,
    }
    payload = signed_payload(
        participant,
        operation="authority.bootstrap_activate",
        nonce="retired-bootstrap-0001",
        body=body,
        now=now,
    )

    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/v1/bootstrap/activate",
            json=payload,
            headers={"Authorization": f"Bearer {(b'b' * 32).decode()}"},
        )
    assert response.status_code == 404


def test_authenticated_durable_kc_bootstrap_journey(tmp_path: Path) -> None:  # noqa: PLR0915
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'kyn.db'}"
    prepare_database(database_url)
    settings = Settings(
        environment="integration",
        database_url=database_url,
        issuer="https://kyn.usparty.party",
        signing_seed_file=write_secret(tmp_path / "signing.seed", b"s" * 32),
        pairwise_secret_file=write_secret(tmp_path / "pairwise.secret", b"p" * 32),
        receipt_secret_file=write_secret(tmp_path / "receipt.secret", b"r" * 32),
        bootstrap_token_file=write_secret(tmp_path / "bootstrap.token", b"b" * 32),
    )
    participant = Ed25519Signer.from_seed("kc-test-participant", b"k" * 32)
    now = datetime.now(tz=UTC).replace(microsecond=0)
    app = create_app(settings)

    with TestClient(app) as client:
        bootstrap_body = {
            "participant_key": participant.participant_key,
            "public_label": "KC Streich",
            "designation_reference": "sha256:" + "a" * 64,
            "policy_version": "1.0.0",
            "expires_at": (now + timedelta(days=365)).isoformat().replace("+00:00", "Z"),
            "release_version": "1.0.0",
            "notice_version": "1.0.0",
            "terms_url": "https://usparty.party/kyn/terms/1.0.0",
            "privacy_url": "https://usparty.party/kyn/privacy/1.0.0",
            "operator_contact": "privacy@usparty.party",
            "storage_posture": "provisional_beta",
            "backup_evidence_reference": "sha256:" + "b" * 64,
            "sensitive_evidence_enabled": False,
        }
        bootstrap_payload = signed_payload(
            participant,
            operation="authority.bootstrap_activate",
            nonce="bootstrap-kc-00000001",
            body=bootstrap_body,
            now=now,
        )
        response = client.post(
            "/v1/bootstrap/activate",
            json=bootstrap_payload,
            headers={"Authorization": f"Bearer {(b'b' * 32).decode()}"},
        )
        assert response.status_code == 201, response.text
        bootstrap_result = response.json()
        subject_id = next(
            item["subject_id"]
            for item in bootstrap_result["records"]
            if item["record_type"] == "subject"
        )
        authority_grant_id = next(
            item["authority_grant_id"]
            for item in bootstrap_result["records"]
            if item["record_type"] == "authority_grant"
        )

        consent_body = {
            "subject_id": subject_id,
            "notice_version": "1.0.0",
            "purposes": ["kyn_claim_processing", "kyn_recovery"],
        }
        consent_payload = signed_payload(
            participant,
            operation="consent.accept",
            nonce="accept-consent-0000001",
            body=consent_body,
            now=now,
        )
        consent_payload.pop("subject_id")
        response = client.post(f"/v1/subjects/{subject_id}/consents", json=consent_payload)
        assert response.status_code == 201, response.text

        claim_body = {
            "actor_authority_grant_id": authority_grant_id,
            "claim_type": "community_corroborated_wisconsin_connection",
            "definition_version": "1.0.0",
            "policy_version": "1.0.0",
            "method_class": "operator_bootstrap",
            "allowed_verification_bases": ["bootstrap_vouched"],
            "required_verification_bases": ["bootstrap_vouched"],
            "minimum_attestations": 1,
            "minimum_independent_paths": 1,
            "minimum_passed_audits": 0,
        }
        response = client.post(
            "/v1/claim-definitions",
            json=signed_payload(
                participant,
                operation="claim_definition.register",
                nonce="register-claim-0000001",
                body=claim_body,
                now=now,
            ),
        )
        assert response.status_code == 201, response.text

        request_body = {
            "subject_id": subject_id,
            "claim_type": "community_corroborated_wisconsin_connection",
            "definition_version": "1.0.0",
            "policy_version": "1.0.0",
        }
        response = client.post(
            "/v1/claim-requests",
            json=signed_payload(
                participant,
                operation="claim.request",
                nonce="request-claim-0000001",
                body=request_body,
                now=now,
            ),
        )
        assert response.status_code == 201, response.text
        request_id = response.json()["records"][0]["request_id"]

        attestation_body = {
            "request_id": request_id,
            "authority_grant_id": authority_grant_id,
            "expires_at": (now + timedelta(days=90)).isoformat().replace("+00:00", "Z"),
        }
        attestation_payload = signed_payload(
            participant,
            operation="attestation.bootstrap_issue",
            nonce="bootstrap-attest-000001",
            body=attestation_body,
            now=now,
        )
        attestation_payload.pop("request_id")
        response = client.post(
            f"/v1/claim-requests/{request_id}/bootstrap-attestation",
            json=attestation_payload,
        )
        assert response.status_code == 200, response.text
        credential = next(
            item for item in response.json()["records"] if item["record_type"] == "credential"
        )
        assert credential["state"] == "active"
        assert credential["verification_bases"] == ["bootstrap_vouched"]

        credential_id = credential["credential_id"]
        presentation_body = {
            "credential_id": credential_id,
            "audience": "ai-for-wisconsin-public-beta",
        }
        presentation_payload = signed_payload(
            participant,
            operation="credential.present",
            nonce="present-credential-0001",
            body=presentation_body,
            now=now,
        )
        presentation_payload.pop("credential_id")
        first = client.post(
            f"/v1/credentials/{credential_id}/presentations",
            json=presentation_payload,
        )
        repeated = client.post(
            f"/v1/credentials/{credential_id}/presentations",
            json=presentation_payload,
        )
        assert first.status_code == 201, first.text
        assert repeated.status_code == 201, repeated.text
        assert repeated.json()["replayed"] is True
        assert repeated.json()["presentation"] == first.json()["presentation"]
        presentation = first.json()["presentation"]
        assert presentation["assurance"]["verification_bases"] == ["bootstrap_vouched"]
        assert "KC Streich" not in str(presentation)
        assert subject_id not in str(presentation)

    # A fresh application process restores the exact durable state.
    with TestClient(create_app(settings)) as restarted:
        response = restarted.get(f"/v1/status/{credential_id}")
        assert response.status_code == 200
        assert response.json()["state"] == "active"


def test_participant_action_rejects_wrong_key(tmp_path: Path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'kyn.db'}"
    prepare_database(database_url)
    settings = Settings(
        environment="integration",
        database_url=database_url,
        issuer="https://kyn.usparty.party",
        signing_seed_file=write_secret(tmp_path / "signing.seed", b"s" * 32),
        pairwise_secret_file=write_secret(tmp_path / "pairwise.secret", b"p" * 32),
        receipt_secret_file=write_secret(tmp_path / "receipt.secret", b"r" * 32),
        bootstrap_token_file=write_secret(tmp_path / "bootstrap.token", b"b" * 32),
    )
    claimed = Ed25519Signer.from_seed("claimed", b"c" * 32)
    attacker = Ed25519Signer.from_seed("attacker", b"a" * 32)
    now = datetime.now(tz=UTC).replace(microsecond=0)
    body = {"participant_key": claimed.participant_key}
    payload = signed_payload(
        attacker,
        operation="subject.create",
        nonce="wrong-key-proof-00001",
        body=body,
        now=now,
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/v1/operator-release").status_code == 503
        response = client.post("/v1/subjects", json=payload)
    assert response.status_code == 401


def test_authenticated_kyn_000c_peer_and_account_lifecycle_routes(tmp_path: Path) -> None:  # noqa: PLR0915
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'kyn-000c.db'}"
    prepare_database(database_url)
    settings = Settings(
        environment="integration",
        database_url=database_url,
        issuer="https://kyn.usparty.party",
        signing_seed_file=write_secret(tmp_path / "signing.seed", b"s" * 32),
        pairwise_secret_file=write_secret(tmp_path / "pairwise.secret", b"p" * 32),
        receipt_secret_file=write_secret(tmp_path / "receipt.secret", b"r" * 32),
        bootstrap_token_file=write_secret(tmp_path / "bootstrap.token", b"b" * 32),
    )
    root = Ed25519Signer.from_seed("kc", b"k" * 32)
    participant = Ed25519Signer.from_seed("participant", b"c" * 32)
    verifier = Ed25519Signer.from_seed("verifier", b"v" * 32)
    replacement = Ed25519Signer.from_seed("replacement", b"n" * 32)
    now = datetime.now(tz=UTC).replace(microsecond=0)
    nonce_counter = 0

    def signed(signer: Ed25519Signer, operation: str, body: dict[str, object]):
        nonlocal nonce_counter
        nonce_counter += 1
        return signed_payload(
            signer,
            operation=operation,
            nonce=f"kyn-000c-action-{nonce_counter:04d}",
            body=body,
            now=now,
        )

    def exact_record(response, record_type: str) -> dict[str, object]:
        assert response.status_code in {200, 201}, response.text
        return next(
            item for item in response.json()["records"] if item["record_type"] == record_type
        )

    with TestClient(create_app(settings)) as client:
        bootstrap_body = {
            "participant_key": root.participant_key,
            "public_label": "KC Streich",
            "designation_reference": "sha256:" + "a" * 64,
            "policy_version": "1.0.0",
            "expires_at": (now + timedelta(days=365)).isoformat().replace("+00:00", "Z"),
            "release_version": "1.0.0",
            "notice_version": "1.0.0",
            "terms_url": "https://usparty.party/kyn/terms/1.0.0",
            "privacy_url": "https://usparty.party/kyn/privacy/1.0.0",
            "operator_contact": "privacy@usparty.party",
            "storage_posture": "provisional_beta",
            "backup_evidence_reference": "sha256:" + "b" * 64,
            "sensitive_evidence_enabled": False,
        }
        bootstrap_response = client.post(
            "/v1/bootstrap/activate",
            json=signed(root, "authority.bootstrap_activate", bootstrap_body),
            headers={"Authorization": f"Bearer {(b'b' * 32).decode()}"},
        )
        root_subject = exact_record(bootstrap_response, "subject")
        root_grant = exact_record(bootstrap_response, "authority_grant")
        root_subject_id = str(root_subject["subject_id"])
        root_grant_id = str(root_grant["authority_grant_id"])
        release = client.get("/v1/operator-release")
        assert release.status_code == 200
        assert release.json()["storage_posture"] == "provisional_beta"

        def create_subject(signer: Ed25519Signer) -> str:
            body = {"participant_key": signer.participant_key}
            return str(
                exact_record(
                    client.post("/v1/subjects", json=signed(signer, "subject.create", body)),
                    "subject",
                )["subject_id"]
            )

        participant_id = create_subject(participant)
        verifier_id = create_subject(verifier)
        consent_body = {
            "notice_version": "1.0.0",
            "purposes": ["kyn_claim_processing", "kyn_recovery"],
        }
        consent_signed = signed(
            participant,
            "consent.accept",
            {"subject_id": participant_id, **consent_body},
        )
        consent_signed.pop("subject_id")
        exact_record(
            client.post(f"/v1/subjects/{participant_id}/consents", json=consent_signed),
            "consent_record",
        )

        claim_type = "community_corroborated_wisconsin_connection"
        method = "peer_corroboration"
        definition_body = {
            "actor_authority_grant_id": root_grant_id,
            "claim_type": claim_type,
            "definition_version": "1.0.0",
            "policy_version": "1.0.0",
            "method_class": method,
            "allowed_verification_bases": ["peer_attested"],
            "required_verification_bases": ["peer_attested"],
            "minimum_attestations": 1,
            "minimum_independent_paths": 1,
            "minimum_passed_audits": 0,
        }
        exact_record(
            client.post(
                "/v1/claim-definitions",
                json=signed(root, "claim_definition.register", definition_body),
            ),
            "claim_definition",
        )
        authority_body = {
            "actor_authority_grant_id": root_grant_id,
            "holder_subject_id": verifier_id,
            "capabilities": ["attest_claim"],
            "claim_types": [claim_type],
            "method_classes": [method],
            "tier": "verifier",
            "expires_at": (now + timedelta(days=90)).isoformat().replace("+00:00", "Z"),
            "usage_cap": 4,
            "can_delegate": False,
            "max_delegation_depth": 1,
            "public_accountability_label": None,
        }
        verifier_grant = exact_record(
            client.post(
                "/v1/authority-grants",
                json=signed(root, "authority.grant", authority_body),
            ),
            "authority_grant",
        )
        verifier_grant_id = str(verifier_grant["authority_grant_id"])
        claim_body = {
            "subject_id": participant_id,
            "claim_type": claim_type,
            "definition_version": "1.0.0",
            "policy_version": "1.0.0",
        }
        claim = exact_record(
            client.post(
                "/v1/claim-requests",
                json=signed(participant, "claim.request", claim_body),
            ),
            "claim_request",
        )
        request_id = str(claim["request_id"])
        invitation_body = {
            "request_id": request_id,
            "verifier_subject_id": verifier_id,
            "expires_at": (now + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        }
        invitation = exact_record(
            client.post(
                "/v1/attestor-invitations",
                json=signed(participant, "attestor.invite", invitation_body),
            ),
            "attestor_invitation",
        )
        introduction_body = {
            "actor_authority_grant_id": root_grant_id,
            "request_id": request_id,
            "introducer_subject_id": root_subject_id,
            "invited_verifier_subject_id": verifier_id,
            "expires_at": (now + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        }
        introduction = exact_record(
            client.post(
                "/v1/introductions",
                json=signed(root, "attestor.introduce", introduction_body),
            ),
            "introduction",
        )
        attestation_body = {
            "invitation_id": str(invitation["invitation_id"]),
            "authority_grant_id": verifier_grant_id,
            "introduction_id": str(introduction["introduction_id"]),
            "method_class": method,
            "expires_at": (now + timedelta(days=30)).isoformat().replace("+00:00", "Z"),
            "verification_basis": "peer_attested",
        }
        invented_path = {
            **attestation_body,
            "introduction_id": "int_invented_path_0001",
        }
        rejected = client.post(
            "/v1/attestations",
            json=signed(verifier, "attestation.issue", invented_path),
        )
        assert rejected.status_code == 409
        assert "requires an introduction" in rejected.json()["detail"]
        attestation_response = client.post(
            "/v1/attestations",
            json=signed(verifier, "attestation.issue", attestation_body),
        )
        attestation = exact_record(attestation_response, "attestation")
        assert str(attestation["independence_path"]).startswith("path_")
        assert root_subject_id not in str(attestation["independence_path"])
        assert exact_record(attestation_response, "credential")["state"] == "active"

        audit_body = {
            "actor_authority_grant_id": root_grant_id,
            "attestation_id": str(attestation["attestation_id"]),
            "basis": "random",
            "selection_seed": "published-random-selection-seed-0001",
        }
        audit = exact_record(
            client.post("/v1/audits", json=signed(root, "audit.select", audit_body)),
            "audit",
        )
        audit_id = str(audit["audit_id"])
        audit_decision_body = {
            "actor_authority_grant_id": root_grant_id,
            "passed": True,
        }
        audit_decision_signed = signed(
            root,
            "audit.decide",
            {"audit_id": audit_id, **audit_decision_body},
        )
        audit_decision_signed.pop("audit_id")
        decided_audit = exact_record(
            client.post(f"/v1/audits/{audit_id}/decision", json=audit_decision_signed),
            "audit",
        )
        assert decided_audit["state"] == "passed"

        challenge_body = {
            "challenger_subject_id": participant_id,
            "attestation_id": str(attestation["attestation_id"]),
            "reason_code": "accuracy_concern",
        }
        challenge = exact_record(
            client.post(
                "/v1/challenges",
                json=signed(participant, "challenge.open", challenge_body),
            ),
            "challenge",
        )
        challenge_id = str(challenge["challenge_id"])
        response_body = {"response_code": "context_supplied"}
        response_signed = signed(
            verifier,
            "challenge.respond",
            {"challenge_id": challenge_id, **response_body},
        )
        response_signed.pop("challenge_id")
        exact_record(
            client.post(f"/v1/challenges/{challenge_id}/response", json=response_signed),
            "challenge",
        )
        challenge_decision_body = {
            "actor_authority_grant_id": root_grant_id,
            "decision": "sustained",
        }
        challenge_decision_signed = signed(
            root,
            "challenge.decide",
            {"challenge_id": challenge_id, **challenge_decision_body},
        )
        challenge_decision_signed.pop("challenge_id")
        exact_record(
            client.post(
                f"/v1/challenges/{challenge_id}/decision",
                json=challenge_decision_signed,
            ),
            "challenge",
        )
        appeal_body = {"appeal_reason_code": "additional_context"}
        appeal_signed = signed(
            verifier,
            "challenge.appeal",
            {"challenge_id": challenge_id, **appeal_body},
        )
        appeal_signed.pop("challenge_id")
        exact_record(
            client.post(f"/v1/challenges/{challenge_id}/appeal", json=appeal_signed),
            "challenge",
        )
        appeal_decision_body = {
            "actor_authority_grant_id": root_grant_id,
            "decision": "reversed",
        }
        appeal_decision_signed = signed(
            root,
            "appeal.decide",
            {"challenge_id": challenge_id, **appeal_decision_body},
        )
        appeal_decision_signed.pop("challenge_id")
        closed = exact_record(
            client.post(
                f"/v1/challenges/{challenge_id}/appeal-decision",
                json=appeal_decision_signed,
            ),
            "challenge",
        )
        assert closed["state"] == "closed"

        recovery_secret = "participant-held-recovery-material-00000001"  # noqa: S105
        commitment_body = {
            "commitment": "sha256:" + hashlib.sha256(recovery_secret.encode()).hexdigest()
        }
        commitment_signed = signed(
            participant,
            "recovery.commitment_register",
            {"subject_id": participant_id, **commitment_body},
        )
        commitment_signed.pop("subject_id")
        exact_record(
            client.post(
                f"/v1/subjects/{participant_id}/recovery-commitments",
                json=commitment_signed,
            ),
            "recovery_commitment",
        )
        recovery_body = {
            "subject_id": participant_id,
            "replacement_participant_key": replacement.participant_key,
            "recovery_secret": recovery_secret,
        }
        recovery = exact_record(
            client.post(
                "/v1/recovery-cases",
                json=signed(replacement, "recovery.request", recovery_body),
            ),
            "recovery_case",
        )
        recovery_id = str(recovery["recovery_case_id"])
        recovery_decision_body = {
            "actor_authority_grant_id": root_grant_id,
            "approve": True,
            "reason_code": "recovery_verified",
        }
        recovery_decision_signed = signed(
            root,
            "recovery.decide",
            {"recovery_case_id": recovery_id, **recovery_decision_body},
        )
        recovery_decision_signed.pop("recovery_case_id")
        exact_record(
            client.post(
                f"/v1/recovery-cases/{recovery_id}/decision",
                json=recovery_decision_signed,
            ),
            "recovery_case",
        )

        privacy_body = {"kind": "export", "reason_code": "participant_requested"}
        privacy_signed = signed(
            replacement,
            "privacy.request",
            {"subject_id": participant_id, **privacy_body},
        )
        privacy_signed.pop("subject_id")
        privacy = exact_record(
            client.post(
                f"/v1/subjects/{participant_id}/privacy-requests",
                json=privacy_signed,
            ),
            "privacy_request",
        )
        privacy_id = str(privacy["privacy_request_id"])
        privacy_decision_body = {
            "actor_authority_grant_id": root_grant_id,
            "approve": True,
            "reason_code": "export_approved",
        }
        privacy_decision_signed = signed(
            root,
            "privacy.process",
            {"privacy_request_id": privacy_id, **privacy_decision_body},
        )
        privacy_decision_signed.pop("privacy_request_id")
        exact_record(
            client.post(
                f"/v1/privacy-requests/{privacy_id}/decision",
                json=privacy_decision_signed,
            ),
            "privacy_request",
        )
        export_signed = signed(
            replacement,
            "privacy.export",
            {"privacy_request_id": privacy_id},
        )
        export_signed.pop("privacy_request_id")
        exported = client.post(f"/v1/privacy-requests/{privacy_id}/export", json=export_signed)
        assert exported.status_code == 200, exported.text
        serialized = str(exported.json()["export"])
        assert participant_id in serialized
        assert verifier.participant_key not in serialized

        next_release_body = {
            "actor_authority_grant_id": root_grant_id,
            "release_version": "1.1.0",
            "notice_version": "1.1.0",
            "terms_url": "https://usparty.party/kyn/terms/1.1.0",
            "privacy_url": "https://usparty.party/kyn/privacy/1.1.0",
            "operator_contact": "privacy@usparty.party",
            "storage_posture": "provisional_beta",
            "backup_evidence_reference": "sha256:" + "c" * 64,
            "sensitive_evidence_enabled": False,
        }
        next_release = exact_record(
            client.post(
                "/v1/operator-releases",
                json=signed(root, "operator_release.register", next_release_body),
            ),
            "operator_release",
        )
        assert next_release["release_version"] == "1.1.0"
        assert next_release["supersedes_release_id"] == release.json()["release_id"]
