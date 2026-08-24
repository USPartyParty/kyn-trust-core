"""Immutable records for the KYN trust state machine.

Private graph records deliberately remain distinct from public status, presentation,
event, and receipt records. None of these types accepts participant PII.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import cast

type JsonValue = bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None


class AssuranceState(StrEnum):
    PROVISIONAL = "provisional"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"


class AttestationState(StrEnum):
    ACTIVE = "active"
    INVALIDATED = "invalidated"
    EXPIRED = "expired"


class AuditBasis(StrEnum):
    RANDOM = "random"
    RISK = "risk"


class AuditState(StrEnum):
    PENDING = "pending"
    PASSED = "passed"
    FAILED = "failed"


class ChallengeState(StrEnum):
    OPEN = "open"
    RESPONDED = "responded"
    DECIDED = "decided"
    APPEALED = "appealed"
    CLOSED = "closed"


class ChallengeDecision(StrEnum):
    DISMISSED = "dismissed"
    SUSTAINED = "sustained"


class AppealDecision(StrEnum):
    AFFIRMED = "affirmed"
    REVERSED = "reversed"


class CredentialState(StrEnum):
    PROVISIONAL = "provisional"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"


class VerificationBasis(StrEnum):
    """Public-safe provenance category for how a claim was established."""

    SELF_ASSERTED = "self_asserted"
    BOOTSTRAP_VOUCHED = "bootstrap_vouched"
    PEER_ATTESTED = "peer_attested"
    OFFICIAL_SOURCE_CHECKED = "official_source_checked"
    INDEPENDENTLY_REVIEWED = "independently_reviewed"
    AUDIT_CORROBORATED = "audit_corroborated"


class AuthorityCapability(StrEnum):
    """Exact actions that may be conferred; tiers never substitute for grants."""

    MANAGE_CLAIMS = "manage_claims"
    INVITE_ATTESTOR = "invite_attestor"
    INTRODUCE_ATTESTOR = "introduce_attestor"
    ATTEST_CLAIM = "attest_claim"
    SELECT_AUDIT = "select_audit"
    DECIDE_AUDIT = "decide_audit"
    DECIDE_CHALLENGE = "decide_challenge"
    DECIDE_APPEAL = "decide_appeal"
    GRANT_AUTHORITY = "grant_authority"
    REVOKE_AUTHORITY = "revoke_authority"
    DECIDE_RECOVERY = "decide_recovery"
    PROCESS_PRIVACY = "process_privacy"
    MANAGE_RELEASE = "manage_release"
    OPERATE_SERVICE = "operate_service"


class AuthorityTier(StrEnum):
    """Named accountability level, not a reputation or social score."""

    PARTICIPANT = "participant"
    PROVISIONAL_VERIFIER = "provisional_verifier"
    VERIFIER = "verifier"
    STEWARD = "steward"
    OPERATOR = "operator"


AUTHORITY_TIER_ORDER: dict[AuthorityTier, int] = {
    AuthorityTier.PARTICIPANT: 0,
    AuthorityTier.PROVISIONAL_VERIFIER: 1,
    AuthorityTier.VERIFIER: 2,
    AuthorityTier.STEWARD: 3,
    AuthorityTier.OPERATOR: 4,
}


class AuthorityBasis(StrEnum):
    BOOTSTRAP_DESIGNATION = "bootstrap_designation"
    DELEGATED = "delegated"
    INDEPENDENT_REVIEW = "independent_review"
    AUDITED_PROMOTION = "audited_promotion"


class StoragePosture(StrEnum):
    PROVISIONAL_BETA = "provisional_beta"
    DURABLE_PRODUCTION = "durable_production"


class RecoveryState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class PrivacyRequestKind(StrEnum):
    EXPORT = "export"
    CORRECTION = "correction"
    DELETION = "deletion"
    CONSENT_WITHDRAWAL = "consent_withdrawal"


class PrivacyRequestState(StrEnum):
    PENDING = "pending"
    COMPLETED = "completed"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class TrustPolicy:
    """Versioned state-machine defaults; claim definitions can be stricter."""

    profile_id: str = "kyn-000a-synthetic-v1"
    required_attestations: int = 2
    required_independent_paths: int = 2
    required_passed_audits: int = 1
    credential_ttl: timedelta = timedelta(days=30)
    presentation_ttl: timedelta = timedelta(minutes=10)
    enforce_authority: bool = False
    enforce_release: bool = False
    require_consent: bool = False
    bootstrap_public_label: str | None = None

    def __post_init__(self) -> None:
        if self.required_attestations < 1:
            raise ValueError("required_attestations must be positive")
        if not 1 <= self.required_independent_paths <= self.required_attestations:
            raise ValueError("independent paths must fit within required attestations")
        if self.required_passed_audits < 0:
            raise ValueError("required_passed_audits cannot be negative")


@dataclass(frozen=True, slots=True)
class SyntheticPolicy(TrustPolicy):
    """Backward-compatible KYN-000A executable test profile."""


@dataclass(frozen=True, slots=True)
class ClaimDefinition:
    claim_type: str
    definition_version: str
    policy_version: str
    method_class: str
    allowed_verification_bases: frozenset[VerificationBasis] = frozenset(
        {VerificationBasis.PEER_ATTESTED}
    )
    required_verification_bases: frozenset[VerificationBasis] = frozenset()
    minimum_attestations: int | None = None
    minimum_independent_paths: int | None = None
    minimum_passed_audits: int | None = None

    def __post_init__(self) -> None:
        if not self.allowed_verification_bases:
            raise ValueError("claim definition requires an allowed verification basis")
        acceptable_required = self.allowed_verification_bases | frozenset(
            {VerificationBasis.AUDIT_CORROBORATED}
        )
        if not self.required_verification_bases <= acceptable_required:
            raise ValueError("required verification bases must be allowed")
        for value in (
            self.minimum_attestations,
            self.minimum_independent_paths,
            self.minimum_passed_audits,
        ):
            if value is not None and value < 0:
                raise ValueError("claim assurance thresholds cannot be negative")
        if (
            self.minimum_attestations is not None
            and self.minimum_independent_paths is not None
            and self.minimum_independent_paths > self.minimum_attestations
        ):
            raise ValueError("independent paths cannot exceed attestations")


@dataclass(frozen=True, slots=True)
class Subject:
    subject_id: str
    participant_key: str | None
    created_at: datetime
    deleted_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class OperatorRelease:
    release_id: str
    release_version: str
    notice_version: str
    terms_url: str
    privacy_url: str
    operator_contact: str
    storage_posture: StoragePosture
    backup_evidence_reference: str
    sensitive_evidence_enabled: bool
    activated_by_authority_grant_id: str
    activated_at: datetime
    supersedes_release_id: str | None = None
    suspended_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class ConsentRecord:
    consent_id: str
    subject_id: str
    notice_version: str
    purposes: frozenset[str]
    granted_at: datetime
    withdrawn_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class RecoveryCommitment:
    recovery_commitment_id: str
    subject_id: str
    commitment: str
    created_at: datetime
    consumed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class RecoveryCase:
    recovery_case_id: str
    subject_id: str
    recovery_commitment_id: str
    prior_key_digest: str
    replacement_participant_key: str
    requested_at: datetime
    state: RecoveryState = RecoveryState.PENDING
    decided_by_authority_grant_id: str | None = None
    decided_at: datetime | None = None
    decision_reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class PrivacyRequest:
    privacy_request_id: str
    subject_id: str
    kind: PrivacyRequestKind
    reason_code: str
    requested_at: datetime
    state: PrivacyRequestState = PrivacyRequestState.PENDING
    decided_by_authority_grant_id: str | None = None
    decided_at: datetime | None = None
    decision_reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class ClaimRequest:
    request_id: str
    subject_id: str
    definition: ClaimDefinition
    requested_at: datetime


@dataclass(frozen=True, slots=True)
class VerifierGrant:
    grant_id: str
    verifier_subject_id: str
    claim_type: str
    method_classes: frozenset[str]
    attestation_cap: int
    issued_at: datetime
    expires_at: datetime
    authority_basis: str
    revoked_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class BootstrapAuthority:
    bootstrap_id: str
    policy_version: str
    authority_subject_id: str
    public_label: str
    designation_reference: str
    activated_at: datetime
    expires_at: datetime
    non_transitive: bool = True


@dataclass(frozen=True, slots=True)
class AuthorityGrant:
    authority_grant_id: str
    holder_subject_id: str
    issuer_authority_grant_id: str | None
    capabilities: frozenset[AuthorityCapability]
    claim_types: frozenset[str]
    method_classes: frozenset[str]
    tier: AuthorityTier
    basis: AuthorityBasis
    issued_at: datetime
    expires_at: datetime
    usage_cap: int | None
    used_count: int
    can_delegate: bool
    delegation_depth: int
    max_delegation_depth: int
    public_accountability_label: str | None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None


@dataclass(frozen=True, slots=True)
class AuthorityPromotion:
    promotion_id: str
    subject_id: str
    source_authority_grant_ids: tuple[str, ...]
    resulting_authority_grant_id: str
    prior_tier: AuthorityTier
    resulting_tier: AuthorityTier
    passed_audit_ids: tuple[str, ...]
    decided_by_authority_grant_id: str
    decided_at: datetime


@dataclass(frozen=True, slots=True)
class AttestorInvitation:
    invitation_id: str
    request_id: str
    verifier_subject_id: str
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class Introduction:
    introduction_id: str
    request_id: str
    introducer_subject_id: str
    invited_verifier_subject_id: str
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class Attestation:
    attestation_id: str
    request_id: str
    grant_id: str
    verifier_subject_id: str
    independence_path: str
    method_class: str
    issued_at: datetime
    expires_at: datetime
    verification_basis: VerificationBasis = VerificationBasis.PEER_ATTESTED
    state: AttestationState = AttestationState.ACTIVE
    invalidation_reason: str | None = None


@dataclass(frozen=True, slots=True)
class Audit:
    audit_id: str
    attestation_id: str
    basis: AuditBasis
    selection_receipt: str
    selected_at: datetime
    state: AuditState = AuditState.PENDING
    decided_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class Challenge:
    challenge_id: str
    attestation_id: str
    reason_code: str
    opened_at: datetime
    state: ChallengeState = ChallengeState.OPEN
    response_code: str | None = None
    decision: ChallengeDecision | None = None
    appeal_reason_code: str | None = None
    appeal_decision: AppealDecision | None = None
    decided_at: datetime | None = None
    challenger_subject_id: str | None = None


@dataclass(frozen=True, slots=True)
class Credential:
    credential_id: str
    request_id: str
    definition: ClaimDefinition
    state: CredentialState
    dependency_attestation_ids: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    status_reference: str
    updated_at: datetime
    verification_bases: tuple[VerificationBasis, ...] = ()


@dataclass(frozen=True, slots=True)
class CredentialStatus:
    status_reference: str
    state: CredentialState
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class PublicEvent:
    event_id: str
    event_type: str
    aggregate_type: str
    occurred_at: datetime
    policy_profile: str
    public_attributes: dict[str, JsonValue] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Receipt:
    receipt_id: str
    operation: str
    outcome: str
    occurred_at: datetime
    event_id: str
    policy_profile: str


@dataclass(frozen=True, slots=True)
class CredentialPresentation:
    presentation_id: str
    issuer: str
    audience: str
    pairwise_subject: str
    claim_type: str
    definition_version: str
    policy_version: str
    assurance_state: AssuranceState
    method_class: str
    verification_bases: tuple[VerificationBasis, ...]
    issued_at: datetime
    expires_at: datetime
    status_reference: str
    receipt_id: str
    proof: dict[str, str]

    def signing_payload(self) -> dict[str, JsonValue]:
        return {
            "presentation_id": self.presentation_id,
            "issuer": self.issuer,
            "audience": self.audience,
            "pairwise_subject": self.pairwise_subject,
            "claim": {
                "type": self.claim_type,
                "definition_version": self.definition_version,
                "policy_version": self.policy_version,
            },
            "assurance": {
                "state": self.assurance_state.value,
                "method_class": self.method_class,
                "verification_bases": [basis.value for basis in self.verification_bases],
            },
            "issued_at": self.issued_at.isoformat().replace("+00:00", "Z"),
            "expires_at": self.expires_at.isoformat().replace("+00:00", "Z"),
            "status_reference": self.status_reference,
            "receipt_id": self.receipt_id,
        }

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            **self.signing_payload(),
            "proof": cast(dict[str, JsonValue], self.proof),
        }


@dataclass(frozen=True, slots=True)
class MemberSnapshot:
    release_version: str
    notice_version: str
    eligible_member_count: int
    generated_at: datetime
    snapshot_digest: str
    proof: dict[str, str]

    def signing_payload(self) -> dict[str, JsonValue]:
        return {
            "release_version": self.release_version,
            "notice_version": self.notice_version,
            "eligible_member_count": self.eligible_member_count,
            "generated_at": self.generated_at.isoformat().replace("+00:00", "Z"),
            "snapshot_digest": self.snapshot_digest,
        }

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            **self.signing_payload(),
            "proof": cast(dict[str, JsonValue], self.proof),
        }


@dataclass(frozen=True, slots=True)
class MemberPresentation:
    presentation_id: str
    issuer: str
    audience: str
    pairwise_subject: str
    determination_version_id: str
    manifest_hash: str
    member_snapshot_digest: str
    release_version: str
    verification_basis: str
    issued_at: datetime
    expires_at: datetime
    receipt_id: str
    proof: dict[str, str]

    def signing_payload(self) -> dict[str, JsonValue]:
        return {
            "presentation_id": self.presentation_id,
            "issuer": self.issuer,
            "audience": self.audience,
            "pairwise_subject": self.pairwise_subject,
            "determination_version_id": self.determination_version_id,
            "manifest_hash": self.manifest_hash,
            "member_snapshot_digest": self.member_snapshot_digest,
            "release_version": self.release_version,
            "verification_basis": self.verification_basis,
            "issued_at": self.issued_at.isoformat().replace("+00:00", "Z"),
            "expires_at": self.expires_at.isoformat().replace("+00:00", "Z"),
            "receipt_id": self.receipt_id,
        }

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            **self.signing_payload(),
            "proof": cast(dict[str, JsonValue], self.proof),
        }
