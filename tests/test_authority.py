from __future__ import annotations

import inspect
from dataclasses import dataclass, fields
from datetime import UTC, datetime, timedelta

import pytest

from kyn import (
    AuditBasis,
    AuthorityBasis,
    AuthorityCapability,
    AuthorityTier,
    ClaimDefinition,
    CredentialState,
    Ed25519Signer,
    TrustCore,
    TrustCoreError,
    TrustPolicy,
    VerificationBasis,
)
from kyn.models import AuthorityGrant

NOW = datetime(2030, 1, 1, tzinfo=UTC)
CLAIM = "community_corroborated_wisconsin_connection"
METHOD = "direct_neighbor_attestation"


@dataclass
class MutableClock:
    value: datetime = NOW

    def __call__(self) -> datetime:
        return self.value


def live_core() -> TrustCore:
    return TrustCore(
        issuer="https://kyn.usparty.party",
        signer=Ed25519Signer.from_seed("kyn-test-live-1", b"k" * 32),
        pairwise_secret=b"p" * 32,
        receipt_secret=b"r" * 32,
        policy=TrustPolicy(
            profile_id="kyn-000b-public-beta-v1",
            enforce_authority=True,
            bootstrap_public_label="KC Streich",
        ),
        clock=MutableClock(),
    )


def bootstrap(core: TrustCore):
    subject, _ = core.create_subject("did:key:zKCTestBootstrapAuthority000001")
    record, grant, _ = core.bootstrap_authority(
        authority_subject_id=subject.subject_id,
        public_label="KC Streich",
        designation_reference="sha256:" + "a" * 64,
        policy_version="1.0.0",
        expires_at=NOW + timedelta(days=365),
    )
    return subject, record, grant


def test_kc_bootstrap_is_single_explicit_and_claim_specific() -> None:
    core = live_core()
    kc, record, grant = bootstrap(core)
    assert record.public_label == "KC Streich"
    assert record.non_transitive is True
    assert grant.tier is AuthorityTier.OPERATOR
    assert grant.basis is AuthorityBasis.BOOTSTRAP_DESIGNATION
    assert AuthorityCapability.GRANT_AUTHORITY in grant.capabilities

    with pytest.raises(TrustCoreError, match="already activated"):
        core.bootstrap_authority(
            authority_subject_id=kc.subject_id,
            public_label="KC Streich",
            designation_reference="sha256:" + "b" * 64,
            policy_version="1.0.0",
            expires_at=NOW + timedelta(days=365),
        )

    definition = ClaimDefinition(
        claim_type=CLAIM,
        definition_version="1.0.0",
        policy_version="1.0.0",
        method_class="operator_bootstrap",
        allowed_verification_bases=frozenset({VerificationBasis.BOOTSTRAP_VOUCHED}),
        required_verification_bases=frozenset({VerificationBasis.BOOTSTRAP_VOUCHED}),
        minimum_attestations=1,
        minimum_independent_paths=1,
        minimum_passed_audits=0,
    )
    with pytest.raises(TrustCoreError, match="explicit authority"):
        core.register_claim(definition)
    core.register_claim(definition, actor_authority_grant_id=grant.authority_grant_id)
    request, _ = core.request_claim(
        subject_id=kc.subject_id,
        claim_type=CLAIM,
        definition_version="1.0.0",
        policy_version="1.0.0",
    )
    _, credential, _ = core.issue_bootstrap_attestation(
        request_id=request.request_id,
        authority_grant_id=grant.authority_grant_id,
        expires_at=NOW + timedelta(days=90),
    )
    assert credential.state is CredentialState.ACTIVE
    assert credential.verification_bases == (VerificationBasis.BOOTSTRAP_VOUCHED,)
    presentation, _ = core.present_credential(
        credential_id=credential.credential_id,
        audience="ai-for-wisconsin-public-beta",
    )
    assert presentation.verification_bases == (VerificationBasis.BOOTSTRAP_VOUCHED,)
    assert "KC Streich" not in str(presentation.as_dict())
    assert kc.subject_id not in str(presentation.as_dict())


def test_delegation_is_subset_scoped_capped_and_non_escalating() -> None:
    core = live_core()
    _, _, root = bootstrap(core)
    verifier, _ = core.create_subject("did:key:zKCTestProvisionalVerifier00001")
    delegated, _ = core.grant_authority(
        actor_authority_grant_id=root.authority_grant_id,
        holder_subject_id=verifier.subject_id,
        capabilities=frozenset(
            {AuthorityCapability.ATTEST_CLAIM, AuthorityCapability.GRANT_AUTHORITY}
        ),
        claim_types=frozenset({CLAIM}),
        method_classes=frozenset({METHOD}),
        tier=AuthorityTier.PROVISIONAL_VERIFIER,
        expires_at=NOW + timedelta(days=60),
        usage_cap=5,
        can_delegate=True,
        max_delegation_depth=2,
        public_accountability_label=None,
    )
    assert delegated.issuer_authority_grant_id == root.authority_grant_id

    with pytest.raises(TrustCoreError, match="above the issuer tier"):
        core.grant_authority(
            actor_authority_grant_id=delegated.authority_grant_id,
            holder_subject_id=verifier.subject_id,
            capabilities=frozenset({AuthorityCapability.ATTEST_CLAIM}),
            claim_types=frozenset({CLAIM}),
            method_classes=frozenset({METHOD}),
            tier=AuthorityTier.OPERATOR,
            expires_at=NOW + timedelta(days=30),
            usage_cap=1,
            can_delegate=False,
            max_delegation_depth=2,
            public_accountability_label="invalid escalation",
        )

    prohibited = {"popularity", "patronage", "donations", "activity", "approval_volume"}
    assert prohibited.isdisjoint({item.name for item in fields(AuthorityGrant)})
    assert prohibited.isdisjoint(inspect.signature(TrustCore.grant_authority).parameters)


def test_audited_procedure_can_promote_one_level() -> None:
    core = live_core()
    kc, _, root = bootstrap(core)
    verifier, _ = core.create_subject("did:key:zKCTestAuditedVerifier000000001")
    participant, _ = core.create_subject("did:key:zKCTestParticipant00000000001")
    definition = ClaimDefinition(
        claim_type=CLAIM,
        definition_version="1.0.0",
        policy_version="1.0.0",
        method_class=METHOD,
        allowed_verification_bases=frozenset({VerificationBasis.PEER_ATTESTED}),
        minimum_attestations=1,
        minimum_independent_paths=1,
        minimum_passed_audits=0,
    )
    core.register_claim(definition, actor_authority_grant_id=root.authority_grant_id)
    request, _ = core.request_claim(
        subject_id=participant.subject_id,
        claim_type=CLAIM,
        definition_version="1.0.0",
        policy_version="1.0.0",
    )
    provisional, _ = core.grant_authority(
        actor_authority_grant_id=root.authority_grant_id,
        holder_subject_id=verifier.subject_id,
        capabilities=frozenset({AuthorityCapability.ATTEST_CLAIM}),
        claim_types=frozenset({CLAIM}),
        method_classes=frozenset({METHOD}),
        tier=AuthorityTier.PROVISIONAL_VERIFIER,
        expires_at=NOW + timedelta(days=90),
        usage_cap=10,
        can_delegate=False,
        max_delegation_depth=1,
        public_accountability_label=None,
    )
    invitation, _ = core.invite_attestor(
        request_id=request.request_id,
        verifier_subject_id=verifier.subject_id,
        expires_at=NOW + timedelta(days=7),
    )
    introduction, _ = core.introduce_attestor(
        request_id=request.request_id,
        introducer_subject_id=kc.subject_id,
        invited_verifier_subject_id=verifier.subject_id,
        expires_at=NOW + timedelta(days=7),
        actor_authority_grant_id=root.authority_grant_id,
    )
    attestation, _, _ = core.issue_attestation(
        invitation_id=invitation.invitation_id,
        grant_id=provisional.authority_grant_id,
        introduction_id=introduction.introduction_id,
        method_class=METHOD,
        expires_at=NOW + timedelta(days=30),
    )
    audit, _ = core.select_audit(
        attestation_id=attestation.attestation_id,
        basis=AuditBasis.RANDOM,
        selection_seed="published-beta-seed-0001",
        actor_authority_grant_id=root.authority_grant_id,
    )
    core.decide_audit(
        audit_id=audit.audit_id,
        passed=True,
        actor_authority_grant_id=root.authority_grant_id,
    )
    promotion, promoted, _ = core.promote_authority(
        actor_authority_grant_id=root.authority_grant_id,
        source_authority_grant_ids=(provisional.authority_grant_id,),
        resulting_tier=AuthorityTier.VERIFIER,
        capabilities=frozenset({AuthorityCapability.ATTEST_CLAIM}),
        expires_at=NOW + timedelta(days=60),
        public_accountability_label=None,
    )
    assert promotion.passed_audit_ids == (audit.audit_id,)
    assert promoted.tier is AuthorityTier.VERIFIER
    assert promoted.basis is AuthorityBasis.AUDITED_PROMOTION
    assert promoted.holder_subject_id != kc.subject_id


def test_revocation_cascades_through_delegated_authority() -> None:
    core = live_core()
    _, _, root = bootstrap(core)
    steward_subject, _ = core.create_subject("did:key:zKCTestSteward00000000000001")
    verifier_subject, _ = core.create_subject("did:key:zKCTestVerifier0000000000001")
    steward, _ = core.grant_authority(
        actor_authority_grant_id=root.authority_grant_id,
        holder_subject_id=steward_subject.subject_id,
        capabilities=frozenset(
            {AuthorityCapability.GRANT_AUTHORITY, AuthorityCapability.ATTEST_CLAIM}
        ),
        claim_types=frozenset({CLAIM}),
        method_classes=frozenset({METHOD}),
        tier=AuthorityTier.STEWARD,
        expires_at=NOW + timedelta(days=90),
        usage_cap=None,
        can_delegate=True,
        max_delegation_depth=2,
        public_accountability_label="Test Steward",
    )
    verifier, _ = core.grant_authority(
        actor_authority_grant_id=steward.authority_grant_id,
        holder_subject_id=verifier_subject.subject_id,
        capabilities=frozenset({AuthorityCapability.ATTEST_CLAIM}),
        claim_types=frozenset({CLAIM}),
        method_classes=frozenset({METHOD}),
        tier=AuthorityTier.PROVISIONAL_VERIFIER,
        expires_at=NOW + timedelta(days=30),
        usage_cap=5,
        can_delegate=False,
        max_delegation_depth=2,
        public_accountability_label=None,
    )
    revoked, _, _ = core.revoke_authority(
        actor_authority_grant_id=root.authority_grant_id,
        authority_grant_id=steward.authority_grant_id,
        reason_code="test_steward_replaced",
    )
    assert {item.authority_grant_id for item in revoked} == {
        steward.authority_grant_id,
        verifier.authority_grant_id,
    }
    assert all(item.revoked_at is not None for item in revoked)


def test_private_snapshot_round_trip_preserves_kc_bootstrap_credential() -> None:
    original = live_core()
    kc, _, root = bootstrap(original)
    definition = ClaimDefinition(
        claim_type=CLAIM,
        definition_version="1.0.0",
        policy_version="1.0.0",
        method_class="operator_bootstrap",
        allowed_verification_bases=frozenset({VerificationBasis.BOOTSTRAP_VOUCHED}),
        required_verification_bases=frozenset({VerificationBasis.BOOTSTRAP_VOUCHED}),
        minimum_attestations=1,
        minimum_independent_paths=1,
        minimum_passed_audits=0,
    )
    original.register_claim(definition, actor_authority_grant_id=root.authority_grant_id)
    request, _ = original.request_claim(
        subject_id=kc.subject_id,
        claim_type=CLAIM,
        definition_version="1.0.0",
        policy_version="1.0.0",
    )
    _, credential, _ = original.issue_bootstrap_attestation(
        request_id=request.request_id,
        authority_grant_id=root.authority_grant_id,
        expires_at=NOW + timedelta(days=90),
    )

    restored = live_core()
    restored.restore_snapshot(original.export_snapshot())
    assert restored.credential_status(credential.status_reference).state is CredentialState.ACTIVE
    presentation, _ = restored.present_credential(
        credential_id=credential.credential_id,
        audience="ai-for-wisconsin-public-beta",
    )
    assert presentation.verification_bases == (VerificationBasis.BOOTSTRAP_VOUCHED,)


def test_private_snapshot_rejects_contract_drift() -> None:
    original = live_core()
    bootstrap(original)
    snapshot = original.export_snapshot()
    authority = next(
        record for record in snapshot["records"] if record["record_type"] == "authority_grant"
    )
    authority["unexpected_field"] = "must-fail-closed"

    with pytest.raises(ValueError, match="exact contract"):
        live_core().restore_snapshot(snapshot)


def test_kyn_000b_snapshot_subject_migrates_to_kyn_000c_shape() -> None:
    original = live_core()
    subject, _, _ = bootstrap(original)
    snapshot = original.export_snapshot()
    snapshot["snapshot_version"] = 1
    subject_record = next(
        record for record in snapshot["records"] if record["record_type"] == "subject"
    )
    subject_record.pop("deleted_at")

    restored = live_core()
    restored.restore_snapshot(snapshot)

    assert restored.participant_key_for_subject(subject.subject_id) == subject.participant_key
