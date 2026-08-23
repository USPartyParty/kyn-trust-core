from __future__ import annotations

import inspect
import json
from dataclasses import asdict, dataclass, fields
from datetime import UTC, datetime, timedelta

import pytest

from kyn import (
    AuditBasis,
    ChallengeDecision,
    ClaimDefinition,
    CredentialState,
    Ed25519Signer,
    Ed25519Verifier,
    TrustCore,
    TrustCoreError,
)
from kyn.models import AppealDecision, VerifierGrant

NOW = datetime(2030, 1, 1, tzinfo=UTC)
CLAIM = "community_corroborated_wisconsin_connection"
METHOD = "two_independent_social_paths"


@dataclass
class MutableClock:
    value: datetime = NOW

    def __call__(self) -> datetime:
        return self.value


@dataclass
class SyntheticJourney:
    core: TrustCore
    clock: MutableClock
    participant_id: str
    verifier_a_id: str
    verifier_b_id: str
    request_id: str
    grant_a_id: str
    grant_b_id: str
    invitation_a_id: str
    invitation_b_id: str


def build_journey(*, cap: int = 2) -> SyntheticJourney:
    clock = MutableClock()
    core = TrustCore(
        issuer="https://kyn.usparty.party",
        signer=Ed25519Signer.from_seed("kyn-synthetic-1", b"k" * 32),
        pairwise_secret=b"p" * 32,
        receipt_secret=b"r" * 32,
        clock=clock,
    )
    core.register_claim(
        ClaimDefinition(
            claim_type=CLAIM,
            definition_version="0.1.0",
            policy_version="0.1.0",
            method_class=METHOD,
        )
    )
    participant, _ = core.create_subject("did:key:zSyntheticParticipant00000001")
    verifier_a, _ = core.create_subject("did:key:zSyntheticVerifierA0000000001")
    verifier_b, _ = core.create_subject("did:key:zSyntheticVerifierB0000000001")
    request, _ = core.request_claim(
        subject_id=participant.subject_id,
        claim_type=CLAIM,
        definition_version="0.1.0",
        policy_version="0.1.0",
    )
    grant_a, _ = core.grant_verifier(
        verifier_subject_id=verifier_a.subject_id,
        claim_type=CLAIM,
        method_classes=frozenset({METHOD}),
        attestation_cap=cap,
        expires_at=NOW + timedelta(days=60),
        authority_basis="synthetic_root_review",
    )
    grant_b, _ = core.grant_verifier(
        verifier_subject_id=verifier_b.subject_id,
        claim_type=CLAIM,
        method_classes=frozenset({METHOD}),
        attestation_cap=cap,
        expires_at=NOW + timedelta(days=60),
        authority_basis="audited_procedure",
    )
    invitation_a, _ = core.invite_attestor(
        request_id=request.request_id,
        verifier_subject_id=verifier_a.subject_id,
        expires_at=NOW + timedelta(days=7),
    )
    invitation_b, _ = core.invite_attestor(
        request_id=request.request_id,
        verifier_subject_id=verifier_b.subject_id,
        expires_at=NOW + timedelta(days=7),
    )
    return SyntheticJourney(
        core=core,
        clock=clock,
        participant_id=participant.subject_id,
        verifier_a_id=verifier_a.subject_id,
        verifier_b_id=verifier_b.subject_id,
        request_id=request.request_id,
        grant_a_id=grant_a.grant_id,
        grant_b_id=grant_b.grant_id,
        invitation_a_id=invitation_a.invitation_id,
        invitation_b_id=invitation_b.invitation_id,
    )


def attest(journey: SyntheticJourney, *, invitation_id: str, grant_id: str, path: str):
    return journey.core.issue_attestation(
        invitation_id=invitation_id,
        grant_id=grant_id,
        independence_path=path,
        method_class=METHOD,
        expires_at=NOW + timedelta(days=30),
    )


def activate(journey: SyntheticJourney):
    attestation_a, first_credential, _ = attest(
        journey,
        invitation_id=journey.invitation_a_id,
        grant_id=journey.grant_a_id,
        path="path_neighborhood_a",
    )
    assert first_credential.state is CredentialState.PROVISIONAL
    attestation_b, corroborated_credential, _ = attest(
        journey,
        invitation_id=journey.invitation_b_id,
        grant_id=journey.grant_b_id,
        path="path_neighborhood_b",
    )
    assert corroborated_credential.state is CredentialState.PROVISIONAL
    audit, _ = journey.core.select_audit(
        attestation_id=attestation_a.attestation_id,
        basis=AuditBasis.RANDOM,
        selection_seed="published-synthetic-seed-1",
    )
    decided_audit, active_credential, _ = journey.core.decide_audit(
        audit_id=audit.audit_id, passed=True
    )
    assert decided_audit.state.value == "passed"
    assert active_credential.state is CredentialState.ACTIVE
    return attestation_a, attestation_b, active_credential


def test_complete_synthetic_state_machine_challenge_and_appeal() -> None:
    journey = build_journey()
    attestation_a, attestation_b, active = activate(journey)

    risk_audit, _ = journey.core.select_audit(
        attestation_id=attestation_b.attestation_id,
        basis=AuditBasis.RISK,
        selection_seed="seeded-risk-case-1",
    )
    assert risk_audit.basis is AuditBasis.RISK
    challenge, _ = journey.core.open_challenge(
        attestation_id=attestation_b.attestation_id,
        reason_code="synthetic_conflict_report",
    )
    responded, _ = journey.core.respond_to_challenge(
        challenge_id=challenge.challenge_id,
        response_code="synthetic_attestor_response",
    )
    assert responded.state.value == "responded"
    decided, revoked, _ = journey.core.decide_challenge(
        challenge_id=challenge.challenge_id,
        decision=ChallengeDecision.SUSTAINED,
    )
    assert decided.decision is ChallengeDecision.SUSTAINED
    assert revoked.credential_id == active.credential_id
    assert revoked.state is CredentialState.REVOKED
    assert journey.core.credential_status(revoked.status_reference).state is CredentialState.REVOKED

    appealed, _ = journey.core.appeal_challenge(
        challenge_id=challenge.challenge_id,
        appeal_reason_code="synthetic_procedure_error",
    )
    assert appealed.state.value == "appealed"
    closed, restored, _ = journey.core.decide_appeal(
        challenge_id=challenge.challenge_id,
        decision=AppealDecision.REVERSED,
    )
    assert closed.appeal_decision is AppealDecision.REVERSED
    assert restored.state is CredentialState.ACTIVE
    assert set(restored.dependency_attestation_ids) == {
        attestation_a.attestation_id,
        attestation_b.attestation_id,
    }


def test_independence_and_verifier_caps_are_enforced() -> None:
    journey = build_journey(cap=1)
    attestation_a, _, _ = attest(
        journey,
        invitation_id=journey.invitation_a_id,
        grant_id=journey.grant_a_id,
        path="path_shared_cluster",
    )
    _, second, _ = attest(
        journey,
        invitation_id=journey.invitation_b_id,
        grant_id=journey.grant_b_id,
        path="path_shared_cluster",
    )
    audit, _ = journey.core.select_audit(
        attestation_id=attestation_a.attestation_id,
        basis=AuditBasis.RANDOM,
        selection_seed="published-seed",
    )
    _, still_provisional, _ = journey.core.decide_audit(audit_id=audit.audit_id, passed=True)
    assert second.state is CredentialState.PROVISIONAL
    assert still_provisional.state is CredentialState.PROVISIONAL

    another, _ = journey.core.create_subject("did:key:zSyntheticSecondParticipant0001")
    request, _ = journey.core.request_claim(
        subject_id=another.subject_id,
        claim_type=CLAIM,
        definition_version="0.1.0",
        policy_version="0.1.0",
    )
    invitation, _ = journey.core.invite_attestor(
        request_id=request.request_id,
        verifier_subject_id=journey.verifier_a_id,
        expires_at=NOW + timedelta(days=7),
    )
    with pytest.raises(TrustCoreError, match="cap"):
        journey.core.issue_attestation(
            invitation_id=invitation.invitation_id,
            grant_id=journey.grant_a_id,
            independence_path="path_other",
            method_class=METHOD,
            expires_at=NOW + timedelta(days=30),
        )


def test_grant_revocation_recalculates_all_dependent_credentials() -> None:
    journey = build_journey()
    _, _, active = activate(journey)
    _, credentials, _ = journey.core.revoke_verifier_grant(
        grant_id=journey.grant_a_id,
        reason_code="synthetic_grant_compromise",
    )
    assert len(credentials) == 1
    assert credentials[0].credential_id == active.credential_id
    assert credentials[0].state is CredentialState.REVOKED


def test_introduction_does_not_confer_transitive_verifier_authority() -> None:
    journey = build_journey()
    introduced, _ = journey.core.create_subject("did:key:zSyntheticIntroducedVerifier0001")
    introduction, _ = journey.core.introduce_attestor(
        request_id=journey.request_id,
        introducer_subject_id=journey.verifier_a_id,
        invited_verifier_subject_id=introduced.subject_id,
        expires_at=NOW + timedelta(days=7),
    )
    assert introduction.invited_verifier_subject_id == introduced.subject_id
    invitation, _ = journey.core.invite_attestor(
        request_id=journey.request_id,
        verifier_subject_id=introduced.subject_id,
        expires_at=NOW + timedelta(days=7),
    )
    with pytest.raises(TrustCoreError, match="do not match"):
        journey.core.issue_attestation(
            invitation_id=invitation.invitation_id,
            grant_id=journey.grant_a_id,
            independence_path="path_introduced",
            method_class=METHOD,
            expires_at=NOW + timedelta(days=30),
        )


def test_expired_dependencies_recalculate_on_status_check() -> None:
    journey = build_journey()
    _, _, active = activate(journey)
    journey.clock.value = NOW + timedelta(days=31)
    status = journey.core.credential_status(active.status_reference)
    assert status.state is CredentialState.EXPIRED


def test_pairwise_presentation_is_signed_and_minimum_disclosure() -> None:
    journey = build_journey()
    _, _, active = activate(journey)
    first, _ = journey.core.present_credential(
        credential_id=active.credential_id, audience="ai-for-wisconsin-pilot"
    )
    repeated, _ = journey.core.present_credential(
        credential_id=active.credential_id, audience="ai-for-wisconsin-pilot"
    )
    other_audience, _ = journey.core.present_credential(
        credential_id=active.credential_id, audience="another-relying-party"
    )
    verifier = Ed25519Verifier(
        key_id=journey.core.signer.key_id,
        public_key=journey.core.signer.public_key,
    )
    assert verifier.verify(first.signing_payload(), first.proof)
    assert first.pairwise_subject == repeated.pairwise_subject
    assert first.pairwise_subject != other_audience.pairwise_subject
    forbidden = {
        "subject_id",
        "participant_key",
        "attestation_id",
        "verifier_subject_id",
        "grant_id",
        "independence_path",
        "evidence",
        "graph",
    }
    assert forbidden.isdisjoint(first.as_dict())
    assert forbidden.isdisjoint(json.loads(json.dumps(first.as_dict())).keys())


def test_receipts_and_public_events_contain_no_private_graph_identifiers() -> None:
    journey = build_journey()
    activate(journey)
    serialized = json.dumps(
        {
            "events": [asdict(event) for event in journey.core.public_events()],
            "receipts": [asdict(receipt) for receipt in journey.core.public_receipts()],
        },
        default=str,
    )
    for private_value in (
        journey.participant_id,
        journey.verifier_a_id,
        journey.verifier_b_id,
        journey.request_id,
        journey.grant_a_id,
        journey.grant_b_id,
    ):
        assert private_value not in serialized


def test_influence_and_activity_are_not_verifier_authority_inputs() -> None:
    model_fields = {item.name for item in fields(VerifierGrant)}
    prohibited = {"popularity", "patronage", "donations", "activity", "approval_volume"}
    assert prohibited.isdisjoint(model_fields)
    signature = inspect.signature(TrustCore.grant_verifier)
    assert prohibited.isdisjoint(signature.parameters)
    journey = build_journey()
    with pytest.raises(TypeError):
        journey.core.grant_verifier(  # type: ignore[call-arg]
            verifier_subject_id=journey.verifier_a_id,
            claim_type=CLAIM,
            method_classes=frozenset({METHOD}),
            attestation_cap=2,
            expires_at=NOW + timedelta(days=60),
            authority_basis="audited_procedure",
            popularity=1_000_000,
        )
