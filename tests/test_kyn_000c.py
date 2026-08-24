from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from kyn import Ed25519Signer, TrustCore, TrustCoreError, TrustPolicy
from kyn.models import (
    ClaimDefinition,
    CredentialState,
    PrivacyRequestKind,
    RecoveryState,
    StoragePosture,
    VerificationBasis,
)

NOW = datetime(2030, 1, 1, tzinfo=UTC)


@dataclass
class Clock:
    value: datetime = NOW

    def __call__(self) -> datetime:
        return self.value


def released_core() -> tuple[TrustCore, str, str]:
    core = TrustCore(
        issuer="https://kyn.usparty.party",
        signer=Ed25519Signer.from_seed("kyn-000c-test", b"k" * 32),
        pairwise_secret=b"p" * 32,
        receipt_secret=b"r" * 32,
        policy=TrustPolicy(
            profile_id="kyn-000c-public-beta-v1",
            enforce_authority=True,
            enforce_release=True,
            require_consent=True,
            bootstrap_public_label="KC Streich",
        ),
        clock=Clock(),
    )
    kc, _ = core.create_subject(
        "did:key:ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        bootstrap=True,
    )
    _, root, _ = core.bootstrap_authority(
        authority_subject_id=kc.subject_id,
        public_label="KC Streich",
        designation_reference="sha256:" + "a" * 64,
        policy_version="1.0.0",
        expires_at=NOW + timedelta(days=365),
    )
    core.register_operator_release(
        actor_authority_grant_id=root.authority_grant_id,
        release_version="2.0.0",
        notice_version="2.0.0",
        terms_url="https://usparty.party/kyn/terms/2.0.0",
        privacy_url="https://usparty.party/kyn/privacy/2.0.0",
        operator_contact="privacy@usparty.party",
        storage_posture=StoragePosture.PROVISIONAL_BETA,
        backup_evidence_reference="sha256:" + "b" * 64,
        sensitive_evidence_enabled=False,
    )
    core.accept_consent(
        subject_id=kc.subject_id,
        notice_version="2.0.0",
        purposes=frozenset({"kyn_claim_processing", "kyn_recovery"}),
    )
    return core, kc.subject_id, root.authority_grant_id


def test_release_consent_and_recovery_rotate_only_the_key_binding() -> None:
    core, kc_subject_id, root_id = released_core()
    participant, _ = core.create_subject(
        "did:key:ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    )
    core.accept_consent(
        subject_id=participant.subject_id,
        notice_version="2.0.0",
        purposes=frozenset({"kyn_claim_processing", "kyn_recovery"}),
    )
    recovery_material = "a-high-entropy-user-held-recovery-secret-0001"
    commitment = f"sha256:{hashlib.sha256(recovery_material.encode()).hexdigest()}"
    core.register_recovery_commitment(subject_id=participant.subject_id, commitment=commitment)
    replacement = "did:key:ed25519:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
    case, _ = core.request_recovery(
        subject_id=participant.subject_id,
        replacement_participant_key=replacement,
        recovery_secret=recovery_material,
    )
    decided, subject, _ = core.decide_recovery(
        recovery_case_id=case.recovery_case_id,
        actor_authority_grant_id=root_id,
        approve=True,
        reason_code="participant_recovery_approved",
    )
    assert decided.state is RecoveryState.APPROVED
    assert subject.subject_id == participant.subject_id
    assert core.participant_key_for_subject(participant.subject_id) == replacement
    assert kc_subject_id != participant.subject_id

    with pytest.raises(TrustCoreError, match="commitment is unavailable"):
        core.request_recovery(
            subject_id=participant.subject_id,
            replacement_participant_key=(
                "did:key:ed25519:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
            ),
            recovery_secret=recovery_material,
        )


def test_privacy_export_is_subject_scoped_and_deletion_invalidates_credentials() -> None:
    core, kc_subject_id, root_id = released_core()
    definition = ClaimDefinition(
        claim_type="bootstrap_wisconsin_connection",
        definition_version="1.0.0",
        policy_version="1.0.0",
        method_class="operator_bootstrap",
        allowed_verification_bases=frozenset({VerificationBasis.BOOTSTRAP_VOUCHED}),
        required_verification_bases=frozenset({VerificationBasis.BOOTSTRAP_VOUCHED}),
        minimum_attestations=1,
        minimum_independent_paths=1,
        minimum_passed_audits=0,
    )
    core.register_claim(definition, actor_authority_grant_id=root_id)
    claim, _ = core.request_claim(
        subject_id=kc_subject_id,
        claim_type=definition.claim_type,
        definition_version="1.0.0",
        policy_version="1.0.0",
    )
    _, credential, _ = core.issue_bootstrap_attestation(
        request_id=claim.request_id,
        authority_grant_id=root_id,
        expires_at=NOW + timedelta(days=30),
    )
    export_request, _ = core.open_privacy_request(
        subject_id=kc_subject_id,
        kind=PrivacyRequestKind.EXPORT,
        reason_code="participant_requested_export",
    )
    core.process_privacy_request(
        privacy_request_id=export_request.privacy_request_id,
        actor_authority_grant_id=root_id,
        approve=True,
        reason_code="export_approved",
    )
    export, _ = core.privacy_export(export_request.privacy_request_id)
    assert {item["record_type"] for item in export["records"]} >= {
        "subject",
        "consent_record",
        "claim_request",
        "credential",
    }

    deletion, _ = core.open_privacy_request(
        subject_id=kc_subject_id,
        kind=PrivacyRequestKind.DELETION,
        reason_code="participant_requested_deletion",
    )
    _, credentials, _ = core.process_privacy_request(
        privacy_request_id=deletion.privacy_request_id,
        actor_authority_grant_id=root_id,
        approve=True,
        reason_code="deletion_approved",
    )
    assert any(item.credential_id == credential.credential_id for item in credentials)
    assert core.credential_status_by_id(credential.credential_id).state is CredentialState.REVOKED
    with pytest.raises(TrustCoreError, match="deleted"):
        core.participant_key_for_subject(kc_subject_id)


def test_release_rejects_sensitive_evidence_and_unreleased_enrollment() -> None:
    core = TrustCore(
        issuer="https://kyn.usparty.party",
        signer=Ed25519Signer.from_seed("unreleased", b"u" * 32),
        pairwise_secret=b"p" * 32,
        receipt_secret=b"r" * 32,
        policy=TrustPolicy(enforce_release=True),
        clock=Clock(),
    )
    with pytest.raises(TrustCoreError, match="release is not active"):
        core.create_subject("did:key:ed25519:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")

    released, _, root_id = released_core()
    with pytest.raises(TrustCoreError, match="does not authorize sensitive evidence"):
        released.register_operator_release(
            actor_authority_grant_id=root_id,
            release_version="1.1.0",
            notice_version="1.1.0",
            terms_url="https://usparty.party/kyn/terms/1.1.0",
            privacy_url="https://usparty.party/kyn/privacy/1.1.0",
            operator_contact="privacy@usparty.party",
            storage_posture=StoragePosture.PROVISIONAL_BETA,
            backup_evidence_reference="sha256:" + "f" * 64,
            sensitive_evidence_enabled=True,
        )
