"""Deterministic KYN trust state machine with explicit scoped authority."""

from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from kyn.contracts import from_record, to_record
from kyn.crypto import Ed25519Signer
from kyn.models import (
    AUTHORITY_TIER_ORDER,
    AppealDecision,
    AssuranceState,
    Attestation,
    AttestationState,
    AttestorInvitation,
    Audit,
    AuditBasis,
    AuditState,
    AuthorityBasis,
    AuthorityCapability,
    AuthorityGrant,
    AuthorityPromotion,
    AuthorityTier,
    BootstrapAuthority,
    Challenge,
    ChallengeDecision,
    ChallengeState,
    ClaimDefinition,
    ClaimRequest,
    ConsentRecord,
    Credential,
    CredentialPresentation,
    CredentialState,
    CredentialStatus,
    Introduction,
    MemberPresentation,
    MemberSnapshot,
    OperatorRelease,
    PrivacyRequest,
    PrivacyRequestKind,
    PrivacyRequestState,
    PublicEvent,
    Receipt,
    RecoveryCase,
    RecoveryCommitment,
    RecoveryState,
    StoragePosture,
    Subject,
    SyntheticPolicy,
    TrustPolicy,
    VerificationBasis,
    VerifierGrant,
)


class TrustCoreError(ValueError):
    """A requested state transition violates the active KYN policy."""


MINIMUM_SECRET_BYTES = 32
SHA256_REFERENCE_LENGTH = 71


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


def _token(prefix: str, digest: bytes) -> str:
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"{prefix}_{encoded}"


class TrustCore:
    """Private trust graph plus privacy-safe presentation and status boundaries.

    KYN-000A uses this engine in memory. KYN-000B added explicit authority and a
    durable adapter; KYN-000C adds release, recovery, privacy, and live peer paths
    without changing the privacy-safe presentation boundary.
    """

    def __init__(
        self,
        *,
        issuer: str,
        signer: Ed25519Signer,
        pairwise_secret: bytes,
        receipt_secret: bytes,
        policy: TrustPolicy | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if (
            len(pairwise_secret) < MINIMUM_SECRET_BYTES
            or len(receipt_secret) < MINIMUM_SECRET_BYTES
        ):
            raise ValueError("KYN secrets must contain at least 32 bytes")
        self.issuer = issuer.rstrip("/")
        self.signer = signer
        self.policy = policy or SyntheticPolicy()
        self._pairwise_secret = pairwise_secret
        self._receipt_secret = receipt_secret
        self._clock = clock
        self._counters: dict[str, int] = {}
        self._subjects: dict[str, Subject] = {}
        self._operator_releases: dict[str, OperatorRelease] = {}
        self._consents: dict[str, ConsentRecord] = {}
        self._recovery_commitments: dict[str, RecoveryCommitment] = {}
        self._recovery_cases: dict[str, RecoveryCase] = {}
        self._privacy_requests: dict[str, PrivacyRequest] = {}
        self._claims: dict[tuple[str, str, str], ClaimDefinition] = {}
        self._requests: dict[str, ClaimRequest] = {}
        self._grants: dict[str, VerifierGrant] = {}
        self._bootstrap_authorities: dict[str, BootstrapAuthority] = {}
        self._authority_grants: dict[str, AuthorityGrant] = {}
        self._authority_promotions: dict[str, AuthorityPromotion] = {}
        self._invitations: dict[str, AttestorInvitation] = {}
        self._introductions: dict[str, Introduction] = {}
        self._attestations: dict[str, Attestation] = {}
        self._audits: dict[str, Audit] = {}
        self._challenges: dict[str, Challenge] = {}
        self._credentials: dict[str, Credential] = {}
        self._credential_by_request: dict[str, str] = {}
        self._events: list[PublicEvent] = []
        self._receipts: list[Receipt] = []

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise RuntimeError("clock must return a timezone-aware datetime")
        return value.astimezone(UTC)

    def _id(self, prefix: str) -> str:
        next_value = self._counters.get(prefix, 0) + 1
        self._counters[prefix] = next_value
        return f"{prefix}_{next_value:08d}"

    def _publish(self, operation: str, outcome: str, aggregate_type: str) -> Receipt:
        now = self._now()
        event_id = self._id("evt")
        receipt_id = _token(
            "rcp",
            hmac.digest(
                self._receipt_secret,
                f"{event_id}|{operation}|{outcome}|{now.isoformat()}".encode(),
                "sha256",
            ),
        )
        event = PublicEvent(
            event_id=event_id,
            event_type=operation,
            aggregate_type=aggregate_type,
            occurred_at=now,
            policy_profile=self.policy.profile_id,
            public_attributes={"outcome": outcome},
        )
        receipt = Receipt(
            receipt_id=receipt_id,
            operation=operation,
            outcome=outcome,
            occurred_at=now,
            event_id=event_id,
            policy_profile=self.policy.profile_id,
        )
        self._events.append(event)
        self._receipts.append(receipt)
        return receipt

    def register_claim(
        self, definition: ClaimDefinition, *, actor_authority_grant_id: str | None = None
    ) -> Receipt:
        self._authorize_if_required(
            actor_authority_grant_id,
            AuthorityCapability.MANAGE_CLAIMS,
            claim_type=definition.claim_type,
        )
        key = (
            definition.claim_type,
            definition.definition_version,
            definition.policy_version,
        )
        if key in self._claims:
            raise TrustCoreError("claim version is already registered")
        self._claims[key] = definition
        return self._publish("claim_definition.registered", "registered", "claim_definition")

    def create_subject(
        self, participant_key: str, *, bootstrap: bool = False
    ) -> tuple[Subject, Receipt]:
        if self.policy.enforce_release and not bootstrap:
            self._require_active_release()
        if not participant_key.startswith("did:key:"):
            raise TrustCoreError("participant key must use did:key")
        if any(subject.participant_key == participant_key for subject in self._subjects.values()):
            raise TrustCoreError("participant key is already enrolled")
        subject = Subject(
            subject_id=self._id("sub"),
            participant_key=participant_key,
            created_at=self._now(),
        )
        self._subjects[subject.subject_id] = subject
        return subject, self._publish("subject.created", "created", "subject")

    def register_operator_release(
        self,
        *,
        actor_authority_grant_id: str,
        release_version: str,
        notice_version: str,
        terms_url: str,
        privacy_url: str,
        operator_contact: str,
        storage_posture: StoragePosture,
        backup_evidence_reference: str,
        sensitive_evidence_enabled: bool,
    ) -> tuple[OperatorRelease, Receipt]:
        actor = self._consume_authority(
            actor_authority_grant_id, AuthorityCapability.MANAGE_RELEASE
        )
        if sensitive_evidence_enabled:
            raise TrustCoreError("KYN-000C does not authorize sensitive evidence")
        if not terms_url.startswith("https://") or not privacy_url.startswith("https://"):
            raise TrustCoreError("release terms and privacy URLs must use https")
        if not operator_contact or "@" not in operator_contact:
            raise TrustCoreError("release requires a public operator contact")
        if (
            not backup_evidence_reference.startswith("sha256:")
            or len(backup_evidence_reference) != SHA256_REFERENCE_LENGTH
        ):
            raise TrustCoreError("release requires a sha256 backup evidence reference")
        active = self.current_operator_release(required=False)
        if active is not None and active.release_version == release_version:
            raise TrustCoreError("operator release version is already active")
        release = OperatorRelease(
            release_id=self._id("rel"),
            release_version=release_version,
            notice_version=notice_version,
            terms_url=terms_url,
            privacy_url=privacy_url,
            operator_contact=operator_contact,
            storage_posture=storage_posture,
            backup_evidence_reference=backup_evidence_reference,
            sensitive_evidence_enabled=False,
            activated_by_authority_grant_id=actor.authority_grant_id,
            activated_at=self._now(),
            supersedes_release_id=active.release_id if active else None,
        )
        if active is not None:
            self._operator_releases[active.release_id] = replace(active, suspended_at=self._now())
        self._operator_releases[release.release_id] = release
        return release, self._publish("operator_release.activated", "active", "release")

    def current_operator_release(self, *, required: bool = True) -> OperatorRelease | None:
        active = [item for item in self._operator_releases.values() if item.suspended_at is None]
        if len(active) == 1:
            return active[0]
        if required:
            raise TrustCoreError("KYN operator release is not active")
        return None

    def accept_consent(
        self, *, subject_id: str, notice_version: str, purposes: frozenset[str]
    ) -> tuple[ConsentRecord, Receipt]:
        self._require_active_release()
        self._require_subject(subject_id)
        release = self.current_operator_release()
        if release is None or notice_version != release.notice_version:
            raise TrustCoreError("consent must bind the active notice version")
        if not purposes or not all(item.startswith("kyn_") for item in purposes):
            raise TrustCoreError("consent requires explicit KYN purposes")
        for consent_id, consent in tuple(self._consents.items()):
            if consent.subject_id == subject_id and consent.withdrawn_at is None:
                self._consents[consent_id] = replace(consent, withdrawn_at=self._now())
        consent = ConsentRecord(
            consent_id=self._id("cns"),
            subject_id=subject_id,
            notice_version=notice_version,
            purposes=purposes,
            granted_at=self._now(),
        )
        self._consents[consent.consent_id] = consent
        return consent, self._publish("consent.accepted", "active", "consent")

    def register_recovery_commitment(
        self, *, subject_id: str, commitment: str
    ) -> tuple[RecoveryCommitment, Receipt]:
        self._require_active_release()
        self._require_subject(subject_id)
        if not commitment.startswith("sha256:") or len(commitment) != SHA256_REFERENCE_LENGTH:
            raise TrustCoreError("recovery commitment must be a sha256 reference")
        if any(
            item.subject_id == subject_id and item.consumed_at is None
            for item in self._recovery_commitments.values()
        ):
            raise TrustCoreError("subject already has an active recovery commitment")
        record = RecoveryCommitment(
            recovery_commitment_id=self._id("rcm"),
            subject_id=subject_id,
            commitment=commitment,
            created_at=self._now(),
        )
        self._recovery_commitments[record.recovery_commitment_id] = record
        return record, self._publish("recovery.commitment_registered", "active", "recovery")

    def request_recovery(
        self,
        *,
        subject_id: str,
        replacement_participant_key: str,
        recovery_secret: str,
    ) -> tuple[RecoveryCase, Receipt]:
        self._require_active_release()
        subject = self._require_subject(subject_id)
        if subject.participant_key is None:
            raise TrustCoreError("deleted subject cannot be recovered")
        if not replacement_participant_key.startswith("did:key:ed25519:"):
            raise TrustCoreError("replacement participant key is invalid")
        if any(
            item.participant_key == replacement_participant_key for item in self._subjects.values()
        ):
            raise TrustCoreError("replacement participant key is already enrolled")
        commitments = [
            item
            for item in self._recovery_commitments.values()
            if item.subject_id == subject_id and item.consumed_at is None
        ]
        if len(commitments) != 1:
            raise TrustCoreError("active recovery commitment is unavailable")
        supplied = f"sha256:{hashlib.sha256(recovery_secret.encode()).hexdigest()}"
        if not hmac.compare_digest(commitments[0].commitment, supplied):
            raise TrustCoreError("recovery secret does not match")
        if any(
            item.subject_id == subject_id and item.state is RecoveryState.PENDING
            for item in self._recovery_cases.values()
        ):
            raise TrustCoreError("subject already has a pending recovery")
        case = RecoveryCase(
            recovery_case_id=self._id("rcv"),
            subject_id=subject_id,
            recovery_commitment_id=commitments[0].recovery_commitment_id,
            prior_key_digest=f"sha256:{hashlib.sha256(subject.participant_key.encode()).hexdigest()}",
            replacement_participant_key=replacement_participant_key,
            requested_at=self._now(),
        )
        self._recovery_cases[case.recovery_case_id] = case
        return case, self._publish("recovery.requested", "pending", "recovery")

    def decide_recovery(
        self,
        *,
        recovery_case_id: str,
        actor_authority_grant_id: str,
        approve: bool,
        reason_code: str,
    ) -> tuple[RecoveryCase, Subject, Receipt]:
        actor = self._consume_authority(
            actor_authority_grant_id, AuthorityCapability.DECIDE_RECOVERY
        )
        try:
            case = self._recovery_cases[recovery_case_id]
        except KeyError as exc:
            raise TrustCoreError("recovery case is unknown") from exc
        if case.state is not RecoveryState.PENDING:
            raise TrustCoreError("recovery case is already decided")
        subject = self._require_subject(case.subject_id)
        state = RecoveryState.APPROVED if approve else RecoveryState.REJECTED
        decided = replace(
            case,
            state=state,
            decided_by_authority_grant_id=actor.authority_grant_id,
            decided_at=self._now(),
            decision_reason_code=reason_code,
        )
        self._recovery_cases[case.recovery_case_id] = decided
        if approve:
            subject = replace(subject, participant_key=case.replacement_participant_key)
            self._subjects[subject.subject_id] = subject
            commitment = self._recovery_commitments[case.recovery_commitment_id]
            self._recovery_commitments[commitment.recovery_commitment_id] = replace(
                commitment, consumed_at=self._now()
            )
        return decided, subject, self._publish("recovery.decided", state.value, "recovery")

    def bootstrap_authority(
        self,
        *,
        authority_subject_id: str,
        public_label: str,
        designation_reference: str,
        policy_version: str,
        expires_at: datetime,
    ) -> tuple[BootstrapAuthority, AuthorityGrant, Receipt]:
        """Activate the single transparent root designated by the accepted policy."""

        self._require_subject(authority_subject_id)
        now = self._now()
        if self._bootstrap_authorities or self._authority_grants:
            raise TrustCoreError("bootstrap authority is already activated")
        if self.policy.bootstrap_public_label is None:
            raise TrustCoreError("active policy does not authorize a bootstrap authority")
        if not hmac.compare_digest(public_label, self.policy.bootstrap_public_label):
            raise TrustCoreError("bootstrap public label does not match the accepted policy")
        if (
            not designation_reference.startswith("sha256:")
            or len(designation_reference) != SHA256_REFERENCE_LENGTH
        ):
            raise TrustCoreError("bootstrap designation requires a sha256 reference")
        if expires_at <= now:
            raise TrustCoreError("bootstrap authority must expire in the future")
        bootstrap = BootstrapAuthority(
            bootstrap_id=self._id("bst"),
            policy_version=policy_version,
            authority_subject_id=authority_subject_id,
            public_label=public_label,
            designation_reference=designation_reference,
            activated_at=now,
            expires_at=expires_at,
        )
        grant = AuthorityGrant(
            authority_grant_id=self._id("agr"),
            holder_subject_id=authority_subject_id,
            issuer_authority_grant_id=None,
            capabilities=frozenset(AuthorityCapability),
            claim_types=frozenset({"*"}),
            method_classes=frozenset({"*"}),
            tier=AuthorityTier.OPERATOR,
            basis=AuthorityBasis.BOOTSTRAP_DESIGNATION,
            issued_at=now,
            expires_at=expires_at,
            usage_cap=None,
            used_count=0,
            can_delegate=True,
            delegation_depth=0,
            max_delegation_depth=4,
            public_accountability_label=public_label,
        )
        self._bootstrap_authorities[bootstrap.bootstrap_id] = bootstrap
        self._authority_grants[grant.authority_grant_id] = grant
        receipt = self._publish("authority.bootstrap_activated", "active", "authority")
        return bootstrap, grant, receipt

    def grant_authority(
        self,
        *,
        actor_authority_grant_id: str,
        holder_subject_id: str,
        capabilities: frozenset[AuthorityCapability],
        claim_types: frozenset[str],
        method_classes: frozenset[str],
        tier: AuthorityTier,
        expires_at: datetime,
        usage_cap: int | None,
        can_delegate: bool,
        max_delegation_depth: int,
        public_accountability_label: str | None,
        basis: AuthorityBasis = AuthorityBasis.DELEGATED,
    ) -> tuple[AuthorityGrant, Receipt]:
        """Delegate a capability subset without creating transitive trust."""

        self._require_subject(holder_subject_id)
        actor = self._validate_authority(
            actor_authority_grant_id, AuthorityCapability.GRANT_AUTHORITY
        )
        now = self._now()
        if not capabilities:
            raise TrustCoreError("authority grant requires at least one capability")
        if not claim_types or not method_classes:
            raise TrustCoreError("authority scope requires claim and method classes")
        if expires_at <= now or expires_at > actor.expires_at:
            raise TrustCoreError("delegated authority expiry must fit within issuer authority")
        if usage_cap is not None and usage_cap < 1:
            raise TrustCoreError("authority usage cap must be positive")
        if AUTHORITY_TIER_ORDER[tier] > AUTHORITY_TIER_ORDER[actor.tier]:
            raise TrustCoreError("delegation cannot raise authority above the issuer tier")
        if not capabilities <= actor.capabilities:
            raise TrustCoreError("delegated capabilities must be a subset of issuer authority")
        if not self._scope_subset(claim_types, actor.claim_types):
            raise TrustCoreError("delegated claim scope exceeds issuer authority")
        if not self._scope_subset(method_classes, actor.method_classes):
            raise TrustCoreError("delegated method scope exceeds issuer authority")
        depth = actor.delegation_depth + 1
        if not actor.can_delegate or depth > actor.max_delegation_depth:
            raise TrustCoreError("issuer authority cannot delegate at this depth")
        if max_delegation_depth < depth or max_delegation_depth > actor.max_delegation_depth:
            raise TrustCoreError("delegation depth exceeds the issuer limit")
        if (
            tier in {AuthorityTier.STEWARD, AuthorityTier.OPERATOR}
            and not public_accountability_label
        ):
            raise TrustCoreError("higher authority requires a public accountability label")
        actor = self._consume_authority(
            actor_authority_grant_id, AuthorityCapability.GRANT_AUTHORITY
        )
        grant = AuthorityGrant(
            authority_grant_id=self._id("agr"),
            holder_subject_id=holder_subject_id,
            issuer_authority_grant_id=actor.authority_grant_id,
            capabilities=capabilities,
            claim_types=claim_types,
            method_classes=method_classes,
            tier=tier,
            basis=basis,
            issued_at=now,
            expires_at=expires_at,
            usage_cap=usage_cap,
            used_count=0,
            can_delegate=can_delegate,
            delegation_depth=depth,
            max_delegation_depth=max_delegation_depth,
            public_accountability_label=public_accountability_label,
        )
        self._authority_grants[grant.authority_grant_id] = grant
        return grant, self._publish("authority.granted", "active", "authority")

    def promote_authority(
        self,
        *,
        actor_authority_grant_id: str,
        source_authority_grant_ids: tuple[str, ...],
        resulting_tier: AuthorityTier,
        capabilities: frozenset[AuthorityCapability],
        expires_at: datetime,
        public_accountability_label: str | None,
    ) -> tuple[AuthorityPromotion, AuthorityGrant, Receipt]:
        """Promote audited conduct by one level; volume and popularity are irrelevant."""

        actor = self._validate_authority(
            actor_authority_grant_id, AuthorityCapability.GRANT_AUTHORITY
        )
        if not source_authority_grant_ids:
            raise TrustCoreError("promotion requires source authority")
        sources = [self._require_authority_grant(item) for item in source_authority_grant_ids]
        if any(item.revoked_at is not None or item.expires_at <= self._now() for item in sources):
            raise TrustCoreError("promotion sources must be active")
        subjects = {item.holder_subject_id for item in sources}
        if len(subjects) != 1:
            raise TrustCoreError("promotion sources must belong to one subject")
        prior_tier = max((item.tier for item in sources), key=AUTHORITY_TIER_ORDER.__getitem__)
        if AUTHORITY_TIER_ORDER[resulting_tier] != AUTHORITY_TIER_ORDER[prior_tier] + 1:
            raise TrustCoreError("promotion must advance exactly one authority tier")
        passed_audits = tuple(
            sorted(
                audit.audit_id
                for audit in self._audits.values()
                if audit.state is AuditState.PASSED
                and self._attestations[audit.attestation_id].verifier_subject_id in subjects
                and self._attestations[audit.attestation_id].state is AttestationState.ACTIVE
            )
        )
        if not passed_audits:
            raise TrustCoreError("promotion requires passed audits of the subject's procedure")
        claim_types = frozenset().union(*(item.claim_types for item in sources))
        method_classes = frozenset().union(*(item.method_classes for item in sources))
        grant, _ = self.grant_authority(
            actor_authority_grant_id=actor.authority_grant_id,
            holder_subject_id=next(iter(subjects)),
            capabilities=capabilities,
            claim_types=claim_types,
            method_classes=method_classes,
            tier=resulting_tier,
            expires_at=expires_at,
            usage_cap=None,
            can_delegate=resulting_tier in {AuthorityTier.STEWARD, AuthorityTier.OPERATOR},
            max_delegation_depth=min(actor.max_delegation_depth, actor.delegation_depth + 2),
            public_accountability_label=public_accountability_label,
            basis=AuthorityBasis.AUDITED_PROMOTION,
        )
        promotion = AuthorityPromotion(
            promotion_id=self._id("prm"),
            subject_id=grant.holder_subject_id,
            source_authority_grant_ids=tuple(sorted(source_authority_grant_ids)),
            resulting_authority_grant_id=grant.authority_grant_id,
            prior_tier=prior_tier,
            resulting_tier=resulting_tier,
            passed_audit_ids=passed_audits,
            decided_by_authority_grant_id=actor.authority_grant_id,
            decided_at=self._now(),
        )
        self._authority_promotions[promotion.promotion_id] = promotion
        return promotion, grant, self._publish("authority.promoted", "active", "authority")

    def revoke_authority(
        self, *, actor_authority_grant_id: str, authority_grant_id: str, reason_code: str
    ) -> tuple[tuple[AuthorityGrant, ...], tuple[Credential, ...], Receipt]:
        actor = self._consume_authority(
            actor_authority_grant_id, AuthorityCapability.REVOKE_AUTHORITY
        )
        target = self._require_authority_grant(authority_grant_id)
        if target.revoked_at is not None:
            raise TrustCoreError("authority grant is already revoked")
        if target.issuer_authority_grant_id != actor.authority_grant_id and (
            AUTHORITY_TIER_ORDER[actor.tier] <= AUTHORITY_TIER_ORDER[target.tier]
        ):
            raise TrustCoreError("actor cannot revoke peer or higher authority")
        now = self._now()
        revoked_ids = {authority_grant_id}
        changed = True
        while changed:
            changed = False
            for grant in self._authority_grants.values():
                if (
                    grant.issuer_authority_grant_id in revoked_ids
                    and grant.authority_grant_id not in revoked_ids
                ):
                    revoked_ids.add(grant.authority_grant_id)
                    changed = True
        revoked: list[AuthorityGrant] = []
        affected_requests: set[str] = set()
        for grant_id in sorted(revoked_ids):
            grant = self._authority_grants[grant_id]
            updated = replace(grant, revoked_at=now, revocation_reason=reason_code)
            self._authority_grants[grant_id] = updated
            revoked.append(updated)
        for attestation_id, attestation in self._attestations.items():
            if attestation.grant_id in revoked_ids and attestation.state is AttestationState.ACTIVE:
                self._attestations[attestation_id] = replace(
                    attestation,
                    state=AttestationState.INVALIDATED,
                    invalidation_reason=reason_code,
                )
                affected_requests.add(attestation.request_id)
        credentials = tuple(
            credential
            for request_id in sorted(affected_requests)
            if (credential := self._recalculate(request_id)) is not None
        )
        return (
            tuple(revoked),
            credentials,
            self._publish("authority.revoked", "revoked", "authority"),
        )

    def request_claim(
        self,
        *,
        subject_id: str,
        claim_type: str,
        definition_version: str,
        policy_version: str,
    ) -> tuple[ClaimRequest, Receipt]:
        self._require_active_release()
        self._require_subject(subject_id)
        if self.policy.require_consent and not self._has_active_consent(
            subject_id, "kyn_claim_processing"
        ):
            raise TrustCoreError("claim request requires active claim-processing consent")
        key = (claim_type, definition_version, policy_version)
        try:
            definition = self._claims[key]
        except KeyError as exc:
            raise TrustCoreError("claim definition is not registered") from exc
        request = ClaimRequest(
            request_id=self._id("clm"),
            subject_id=subject_id,
            definition=definition,
            requested_at=self._now(),
        )
        self._requests[request.request_id] = request
        return request, self._publish("claim.requested", "pending", "claim_request")

    def open_privacy_request(
        self, *, subject_id: str, kind: PrivacyRequestKind, reason_code: str
    ) -> tuple[PrivacyRequest, Receipt]:
        self._require_subject(subject_id)
        if any(
            item.subject_id == subject_id
            and item.kind is kind
            and item.state is PrivacyRequestState.PENDING
            for item in self._privacy_requests.values()
        ):
            raise TrustCoreError("matching privacy request is already pending")
        privacy_request = PrivacyRequest(
            privacy_request_id=self._id("prv"),
            subject_id=subject_id,
            kind=kind,
            reason_code=reason_code,
            requested_at=self._now(),
        )
        self._privacy_requests[privacy_request.privacy_request_id] = privacy_request
        return privacy_request, self._publish("privacy.requested", "pending", "privacy")

    def process_privacy_request(
        self,
        *,
        privacy_request_id: str,
        actor_authority_grant_id: str,
        approve: bool,
        reason_code: str,
    ) -> tuple[PrivacyRequest, tuple[Credential, ...], Receipt]:
        actor = self._consume_authority(
            actor_authority_grant_id, AuthorityCapability.PROCESS_PRIVACY
        )
        try:
            request = self._privacy_requests[privacy_request_id]
        except KeyError as exc:
            raise TrustCoreError("privacy request is unknown") from exc
        if request.state is not PrivacyRequestState.PENDING:
            raise TrustCoreError("privacy request is already decided")
        state = PrivacyRequestState.COMPLETED if approve else PrivacyRequestState.REJECTED
        decided = replace(
            request,
            state=state,
            decided_by_authority_grant_id=actor.authority_grant_id,
            decided_at=self._now(),
            decision_reason_code=reason_code,
        )
        self._privacy_requests[privacy_request_id] = decided
        credentials: tuple[Credential, ...] = ()
        if approve and request.kind in {
            PrivacyRequestKind.CONSENT_WITHDRAWAL,
            PrivacyRequestKind.DELETION,
            PrivacyRequestKind.CORRECTION,
        }:
            credentials = self._invalidate_subject_state(
                request.subject_id, reason=f"privacy_{request.kind.value}"
            )
        if approve and request.kind in {
            PrivacyRequestKind.CONSENT_WITHDRAWAL,
            PrivacyRequestKind.DELETION,
        }:
            for consent_id, consent in tuple(self._consents.items()):
                if consent.subject_id == request.subject_id and consent.withdrawn_at is None:
                    self._consents[consent_id] = replace(consent, withdrawn_at=self._now())
        if approve and request.kind is PrivacyRequestKind.DELETION:
            subject = self._require_subject(request.subject_id)
            self._subjects[subject.subject_id] = replace(
                subject, participant_key=None, deleted_at=self._now()
            )
        return decided, credentials, self._publish("privacy.processed", state.value, "privacy")

    def privacy_export(self, privacy_request_id: str) -> tuple[dict[str, Any], Receipt]:
        try:
            request = self._privacy_requests[privacy_request_id]
        except KeyError as exc:
            raise TrustCoreError("privacy request is unknown") from exc
        if (
            request.kind is not PrivacyRequestKind.EXPORT
            or request.state is not PrivacyRequestState.COMPLETED
        ):
            raise TrustCoreError("completed export request is required")
        subject_id = request.subject_id
        request_ids = {
            item.request_id for item in self._requests.values() if item.subject_id == subject_id
        }
        attestation_ids = {
            item.attestation_id
            for item in self._attestations.values()
            if item.request_id in request_ids or item.verifier_subject_id == subject_id
        }
        records: list[object] = [self._require_subject(subject_id)]
        records.extend(item for item in self._consents.values() if item.subject_id == subject_id)
        records.extend(item for item in self._requests.values() if item.subject_id == subject_id)
        records.extend(
            item
            for item in self._invitations.values()
            if item.request_id in request_ids or item.verifier_subject_id == subject_id
        )
        records.extend(
            item for item in self._authority_grants.values() if item.holder_subject_id == subject_id
        )
        records.extend(
            item
            for item in self._attestations.values()
            if item.request_id in request_ids or item.verifier_subject_id == subject_id
        )
        records.extend(
            item for item in self._audits.values() if item.attestation_id in attestation_ids
        )
        records.extend(
            item for item in self._challenges.values() if item.attestation_id in attestation_ids
        )
        records.extend(
            item for item in self._credentials.values() if item.request_id in request_ids
        )
        records.extend(
            item for item in self._recovery_commitments.values() if item.subject_id == subject_id
        )
        records.extend(
            item for item in self._recovery_cases.values() if item.subject_id == subject_id
        )
        records.extend(
            item for item in self._privacy_requests.values() if item.subject_id == subject_id
        )
        receipt = self._publish("privacy.exported", "completed", "privacy")
        return {
            "export_version": 1,
            "generated_at": self._now().isoformat().replace("+00:00", "Z"),
            "records": [to_record(item) for item in records],  # type: ignore[arg-type]
        }, receipt

    def grant_verifier(
        self,
        *,
        verifier_subject_id: str,
        claim_type: str,
        method_classes: frozenset[str],
        attestation_cap: int,
        expires_at: datetime,
        authority_basis: str,
    ) -> tuple[VerifierGrant, Receipt]:
        if self.policy.enforce_authority:
            raise TrustCoreError("live policy requires a scoped authority grant")
        self._require_subject(verifier_subject_id)
        if attestation_cap < 1:
            raise TrustCoreError("verifier cap must be positive")
        if not method_classes:
            raise TrustCoreError("verifier grant requires a method class")
        if expires_at <= self._now():
            raise TrustCoreError("verifier grant must expire in the future")
        if authority_basis not in {"synthetic_root_review", "audited_procedure"}:
            raise TrustCoreError("authority basis must be approved procedure, not influence")
        grant = VerifierGrant(
            grant_id=self._id("grt"),
            verifier_subject_id=verifier_subject_id,
            claim_type=claim_type,
            method_classes=method_classes,
            attestation_cap=attestation_cap,
            issued_at=self._now(),
            expires_at=expires_at,
            authority_basis=authority_basis,
        )
        self._grants[grant.grant_id] = grant
        return grant, self._publish("verifier_grant.issued", "active", "verifier_grant")

    def invite_attestor(
        self,
        *,
        request_id: str,
        verifier_subject_id: str,
        expires_at: datetime,
    ) -> tuple[AttestorInvitation, Receipt]:
        request = self._require_request(request_id)
        self._require_subject(verifier_subject_id)
        if request.subject_id == verifier_subject_id:
            raise TrustCoreError("a subject cannot attest its own claim")
        if expires_at <= self._now():
            raise TrustCoreError("invitation must expire in the future")
        invitation = AttestorInvitation(
            invitation_id=self._id("inv"),
            request_id=request_id,
            verifier_subject_id=verifier_subject_id,
            created_at=self._now(),
            expires_at=expires_at,
        )
        self._invitations[invitation.invitation_id] = invitation
        return invitation, self._publish("attestor.invited", "pending", "invitation")

    def introduce_attestor(
        self,
        *,
        request_id: str,
        introducer_subject_id: str,
        invited_verifier_subject_id: str,
        expires_at: datetime,
        actor_authority_grant_id: str | None = None,
    ) -> tuple[Introduction, Receipt]:
        self._authorize_if_required(
            actor_authority_grant_id, AuthorityCapability.INTRODUCE_ATTESTOR
        )
        request = self._require_request(request_id)
        self._require_subject(introducer_subject_id)
        self._require_subject(invited_verifier_subject_id)
        if request.subject_id in {introducer_subject_id, invited_verifier_subject_id}:
            raise TrustCoreError("a claim subject cannot create its own verification path")
        if introducer_subject_id == invited_verifier_subject_id:
            raise TrustCoreError("introduction requires two distinct parties")
        if expires_at <= self._now():
            raise TrustCoreError("introduction must expire in the future")
        introduction = Introduction(
            introduction_id=self._id("int"),
            request_id=request_id,
            introducer_subject_id=introducer_subject_id,
            invited_verifier_subject_id=invited_verifier_subject_id,
            created_at=self._now(),
            expires_at=expires_at,
        )
        self._introductions[introduction.introduction_id] = introduction
        return introduction, self._publish("attestor.introduced", "pending", "introduction")

    def issue_attestation(
        self,
        *,
        invitation_id: str,
        grant_id: str,
        method_class: str,
        expires_at: datetime,
        verification_basis: VerificationBasis = VerificationBasis.PEER_ATTESTED,
        introduction_id: str | None = None,
        independence_path: str | None = None,
    ) -> tuple[Attestation, Credential, Receipt]:
        now = self._now()
        try:
            invitation = self._invitations[invitation_id]
        except KeyError as exc:
            raise TrustCoreError("attestor invitation is unknown") from exc
        request = self._require_request(invitation.request_id)
        if verification_basis not in request.definition.allowed_verification_bases:
            raise TrustCoreError("verification basis is not allowed by the claim policy")
        if verification_basis is VerificationBasis.AUDIT_CORROBORATED:
            raise TrustCoreError("audit-corroborated basis can only result from an audit")
        verifier_subject_id, grant_expires_at, attestation_cap = (
            self._resolve_attestation_authority(
                grant_id=grant_id,
                request=request,
                method_class=method_class,
                now=now,
            )
        )
        if invitation.expires_at <= now:
            raise TrustCoreError("attestor invitation has expired")
        if invitation.verifier_subject_id != verifier_subject_id:
            raise TrustCoreError("invitation and verifier grant do not match")
        independence_path = self._resolve_independence_path(
            request=request,
            verifier_subject_id=verifier_subject_id,
            verification_basis=verification_basis,
            introduction_id=introduction_id,
            fallback=independence_path,
            now=now,
        )
        if expires_at <= now or expires_at > grant_expires_at:
            raise TrustCoreError("attestation expiry must fit within the verifier grant")
        existing = self._active_attestations(request.request_id, now)
        if any(item.verifier_subject_id == verifier_subject_id for item in existing):
            raise TrustCoreError("the same verifier cannot corroborate a request twice")
        grant_active = [
            item
            for item in self._attestations.values()
            if item.grant_id == grant_id
            and item.state is AttestationState.ACTIVE
            and item.expires_at > now
        ]
        if attestation_cap is not None and len(grant_active) >= attestation_cap:
            raise TrustCoreError("verifier attestation cap has been reached")
        attestation = Attestation(
            attestation_id=self._id("att"),
            request_id=request.request_id,
            grant_id=grant_id,
            verifier_subject_id=verifier_subject_id,
            independence_path=independence_path,
            method_class=method_class,
            issued_at=now,
            expires_at=expires_at,
            verification_basis=verification_basis,
        )
        self._attestations[attestation.attestation_id] = attestation
        credential = self._recalculate(request.request_id)
        if credential is None:
            raise RuntimeError("an attestation must produce a provisional credential")
        return (
            attestation,
            credential,
            self._publish("attestation.issued", credential.state.value, "attestation"),
        )

    def issue_bootstrap_attestation(
        self,
        *,
        request_id: str,
        authority_grant_id: str,
        expires_at: datetime,
    ) -> tuple[Attestation, Credential, Receipt]:
        """Record the initial steward's claim without pretending it is peer review."""

        request = self._require_request(request_id)
        grant = self._consume_authority(
            authority_grant_id,
            AuthorityCapability.ATTEST_CLAIM,
            claim_type=request.definition.claim_type,
            method_class=request.definition.method_class,
        )
        if grant.basis is not AuthorityBasis.BOOTSTRAP_DESIGNATION:
            raise TrustCoreError("only the designated bootstrap authority may use this path")
        if request.subject_id != grant.holder_subject_id:
            raise TrustCoreError("bootstrap attestation is limited to the designated subject")
        if VerificationBasis.BOOTSTRAP_VOUCHED not in (
            request.definition.allowed_verification_bases
        ):
            raise TrustCoreError("claim policy does not allow bootstrap-vouched assurance")
        now = self._now()
        if expires_at <= now or expires_at > grant.expires_at:
            raise TrustCoreError("bootstrap attestation expiry must fit within authority")
        if self._active_attestations(request_id, now):
            raise TrustCoreError("bootstrap claim already has an active attestation")
        attestation = Attestation(
            attestation_id=self._id("att"),
            request_id=request_id,
            grant_id=grant.authority_grant_id,
            verifier_subject_id=grant.holder_subject_id,
            independence_path="path_bootstrap_designation",
            method_class=request.definition.method_class,
            issued_at=now,
            expires_at=expires_at,
            verification_basis=VerificationBasis.BOOTSTRAP_VOUCHED,
        )
        self._attestations[attestation.attestation_id] = attestation
        credential = self._recalculate(request_id)
        if credential is None:
            raise RuntimeError("bootstrap attestation must produce a credential")
        return (
            attestation,
            credential,
            self._publish("attestation.bootstrap_issued", credential.state.value, "attestation"),
        )

    def select_audit(
        self,
        *,
        attestation_id: str,
        basis: AuditBasis,
        selection_seed: str,
        actor_authority_grant_id: str | None = None,
    ) -> tuple[Audit, Receipt]:
        self._authorize_if_required(actor_authority_grant_id, AuthorityCapability.SELECT_AUDIT)
        attestation = self._require_attestation(attestation_id)
        if attestation.state is not AttestationState.ACTIVE:
            raise TrustCoreError("only active attestations can be audited")
        if any(audit.attestation_id == attestation_id for audit in self._audits.values()):
            raise TrustCoreError("attestation is already selected for audit")
        digest = hmac.digest(
            self._receipt_secret,
            f"{attestation_id}|{basis.value}|{selection_seed}".encode(),
            "sha256",
        )
        audit = Audit(
            audit_id=self._id("aud"),
            attestation_id=attestation_id,
            basis=basis,
            selection_receipt=_token("sel", digest),
            selected_at=self._now(),
        )
        self._audits[audit.audit_id] = audit
        return audit, self._publish("audit.selected", "pending", "audit")

    def decide_audit(
        self,
        *,
        audit_id: str,
        passed: bool,
        actor_authority_grant_id: str | None = None,
    ) -> tuple[Audit, Credential, Receipt]:
        self._authorize_if_required(actor_authority_grant_id, AuthorityCapability.DECIDE_AUDIT)
        try:
            audit = self._audits[audit_id]
        except KeyError as exc:
            raise TrustCoreError("audit is unknown") from exc
        if audit.state is not AuditState.PENDING:
            raise TrustCoreError("audit is already decided")
        decided = replace(
            audit,
            state=AuditState.PASSED if passed else AuditState.FAILED,
            decided_at=self._now(),
        )
        self._audits[audit_id] = decided
        attestation = self._require_attestation(audit.attestation_id)
        if not passed:
            self._attestations[attestation.attestation_id] = replace(
                attestation,
                state=AttestationState.INVALIDATED,
                invalidation_reason="audit_failed",
            )
        credential = self._recalculate(attestation.request_id)
        if credential is None:
            raise RuntimeError("audited attestation must have a dependent credential")
        return (
            decided,
            credential,
            self._publish("audit.decided", decided.state.value, "audit"),
        )

    def open_challenge(
        self, *, attestation_id: str, reason_code: str, challenger_subject_id: str | None = None
    ) -> tuple[Challenge, Receipt]:
        attestation = self._require_attestation(attestation_id)
        if challenger_subject_id is not None:
            self._require_subject(challenger_subject_id)
        if attestation.state is not AttestationState.ACTIVE:
            raise TrustCoreError("only active attestations can be challenged")
        challenge = Challenge(
            challenge_id=self._id("chg"),
            attestation_id=attestation_id,
            reason_code=reason_code,
            opened_at=self._now(),
            challenger_subject_id=challenger_subject_id,
        )
        self._challenges[challenge.challenge_id] = challenge
        return challenge, self._publish("challenge.opened", "open", "challenge")

    def respond_to_challenge(
        self, *, challenge_id: str, response_code: str
    ) -> tuple[Challenge, Receipt]:
        challenge = self._require_challenge(challenge_id)
        if challenge.state is not ChallengeState.OPEN:
            raise TrustCoreError("challenge is not awaiting a response")
        updated = replace(
            challenge,
            state=ChallengeState.RESPONDED,
            response_code=response_code,
        )
        self._challenges[challenge_id] = updated
        return updated, self._publish("challenge.responded", "responded", "challenge")

    def decide_challenge(
        self,
        *,
        challenge_id: str,
        decision: ChallengeDecision,
        actor_authority_grant_id: str | None = None,
    ) -> tuple[Challenge, Credential, Receipt]:
        self._authorize_if_required(actor_authority_grant_id, AuthorityCapability.DECIDE_CHALLENGE)
        challenge = self._require_challenge(challenge_id)
        if challenge.state not in {ChallengeState.OPEN, ChallengeState.RESPONDED}:
            raise TrustCoreError("challenge cannot be decided in its current state")
        updated = replace(
            challenge,
            state=ChallengeState.DECIDED,
            decision=decision,
            decided_at=self._now(),
        )
        self._challenges[challenge_id] = updated
        attestation = self._require_attestation(challenge.attestation_id)
        if decision is ChallengeDecision.SUSTAINED:
            self._attestations[attestation.attestation_id] = replace(
                attestation,
                state=AttestationState.INVALIDATED,
                invalidation_reason="challenge_sustained",
            )
        credential = self._recalculate(attestation.request_id)
        if credential is None:
            raise RuntimeError("challenged attestation must have a dependent credential")
        return (
            updated,
            credential,
            self._publish("challenge.decided", decision.value, "challenge"),
        )

    def appeal_challenge(
        self, *, challenge_id: str, appeal_reason_code: str
    ) -> tuple[Challenge, Receipt]:
        challenge = self._require_challenge(challenge_id)
        if challenge.state is not ChallengeState.DECIDED:
            raise TrustCoreError("only a decided challenge can be appealed")
        updated = replace(
            challenge,
            state=ChallengeState.APPEALED,
            appeal_reason_code=appeal_reason_code,
        )
        self._challenges[challenge_id] = updated
        return updated, self._publish("challenge.appealed", "appealed", "challenge")

    def decide_appeal(
        self,
        *,
        challenge_id: str,
        decision: AppealDecision,
        actor_authority_grant_id: str | None = None,
    ) -> tuple[Challenge, Credential, Receipt]:
        self._authorize_if_required(actor_authority_grant_id, AuthorityCapability.DECIDE_APPEAL)
        challenge = self._require_challenge(challenge_id)
        if challenge.state is not ChallengeState.APPEALED:
            raise TrustCoreError("challenge is not under appeal")
        updated = replace(
            challenge,
            state=ChallengeState.CLOSED,
            appeal_decision=decision,
            decided_at=self._now(),
        )
        self._challenges[challenge_id] = updated
        attestation = self._require_attestation(challenge.attestation_id)
        if (
            decision is AppealDecision.REVERSED
            and challenge.decision is ChallengeDecision.SUSTAINED
            and self._grant_is_active(attestation.grant_id, self._now())
            and attestation.expires_at > self._now()
        ):
            self._attestations[attestation.attestation_id] = replace(
                attestation,
                state=AttestationState.ACTIVE,
                invalidation_reason=None,
            )
        credential = self._recalculate(attestation.request_id)
        if credential is None:
            raise RuntimeError("appealed attestation must have a dependent credential")
        return (
            updated,
            credential,
            self._publish("appeal.decided", decision.value, "challenge"),
        )

    def revoke_verifier_grant(
        self, *, grant_id: str, reason_code: str
    ) -> tuple[VerifierGrant, tuple[Credential, ...], Receipt]:
        try:
            grant = self._grants[grant_id]
        except KeyError as exc:
            raise TrustCoreError("verifier grant is unknown") from exc
        if grant.revoked_at is not None:
            raise TrustCoreError("verifier grant is already revoked")
        updated = replace(grant, revoked_at=self._now())
        self._grants[grant_id] = updated
        affected_requests: set[str] = set()
        for attestation_id, attestation in self._attestations.items():
            if attestation.grant_id == grant_id and attestation.state is AttestationState.ACTIVE:
                self._attestations[attestation_id] = replace(
                    attestation,
                    state=AttestationState.INVALIDATED,
                    invalidation_reason=reason_code,
                )
                affected_requests.add(attestation.request_id)
        credentials = tuple(
            credential
            for request_id in sorted(affected_requests)
            if (credential := self._recalculate(request_id)) is not None
        )
        return (
            updated,
            credentials,
            self._publish("verifier_grant.revoked", "revoked", "verifier_grant"),
        )

    def credential_status(self, status_reference: str) -> CredentialStatus:
        matches = [
            credential
            for credential in self._credentials.values()
            if credential.status_reference == status_reference
        ]
        if len(matches) != 1:
            raise TrustCoreError("credential status is unavailable")
        credential = matches[0]
        recalculated = self._recalculate(credential.request_id)
        if recalculated is not None:
            credential = recalculated
        state = credential.state
        if credential.expires_at <= self._now():
            state = CredentialState.EXPIRED
        return CredentialStatus(
            status_reference=status_reference,
            state=state,
            updated_at=credential.updated_at,
        )

    def present_credential(
        self, *, credential_id: str, audience: str
    ) -> tuple[CredentialPresentation, Receipt]:
        try:
            credential = self._credentials[credential_id]
            request = self._requests[credential.request_id]
        except KeyError as exc:
            raise TrustCoreError("credential is unknown") from exc
        now = self._now()
        if credential.state not in {CredentialState.PROVISIONAL, CredentialState.ACTIVE}:
            raise TrustCoreError("credential is not presentable")
        if credential.expires_at <= now:
            raise TrustCoreError("credential has expired")
        pairwise = _token(
            "pws",
            hmac.digest(
                self._pairwise_secret,
                f"{request.subject_id}|{audience}".encode(),
                "sha256",
            ),
        )
        receipt = self._publish("credential.presented", "issued", "presentation")
        unsigned = CredentialPresentation(
            presentation_id=self._id("prs"),
            issuer=self.issuer,
            audience=audience,
            pairwise_subject=pairwise,
            claim_type=credential.definition.claim_type,
            definition_version=credential.definition.definition_version,
            policy_version=credential.definition.policy_version,
            assurance_state=AssuranceState(credential.state.value),
            method_class=credential.definition.method_class,
            verification_bases=credential.verification_bases,
            issued_at=now,
            expires_at=min(credential.expires_at, now + self.policy.presentation_ttl),
            status_reference=credential.status_reference,
            receipt_id=receipt.receipt_id,
            proof={},
        )
        presentation = replace(unsigned, proof=self.signer.sign(unsigned.signing_payload()))
        return presentation, receipt

    def member_snapshot(self) -> MemberSnapshot:
        release = self.current_operator_release()
        if release is None or release.release_version != "2.0.0":
            raise TrustCoreError("ordinary member enrollment is not active")
        generated_at = self._now()
        eligible_subjects, snapshot_digest = self._member_snapshot_values(
            release_version=release.release_version,
            notice_version=release.notice_version,
            at=generated_at,
        )
        unsigned = MemberSnapshot(
            release_version=release.release_version,
            notice_version=release.notice_version,
            eligible_member_count=len(eligible_subjects),
            generated_at=generated_at,
            snapshot_digest=snapshot_digest,
            proof={},
        )
        return replace(unsigned, proof=self.signer.sign(unsigned.signing_payload()))

    def present_member(
        self,
        *,
        subject_id: str,
        audience: str,
        determination_version_id: str,
        manifest_hash: str,
        member_snapshot_digest: str,
        member_snapshot_generated_at: datetime,
        requested_expires_at: datetime,
    ) -> tuple[MemberPresentation, Receipt]:
        release = self.current_operator_release()
        if release is None or release.release_version != "2.0.0":
            raise TrustCoreError("ordinary member ballot presentations are not active")
        subject = self._require_subject(subject_id)
        if subject.deleted_at is not None or subject.participant_key is None:
            raise TrustCoreError("member subject is unavailable")
        if not self._has_active_consent(subject_id, "kyn_campaign_member_ballot"):
            raise TrustCoreError("member ballot consent is not active")
        if not audience.startswith("https://"):
            raise TrustCoreError("member presentation audience must use https")
        if not manifest_hash.startswith("sha256:") or len(manifest_hash) != SHA256_REFERENCE_LENGTH:
            raise TrustCoreError("member presentation requires the immutable manifest hash")
        if (
            member_snapshot_generated_at.tzinfo is None
            or member_snapshot_generated_at.utcoffset() is None
        ):
            raise TrustCoreError("member snapshot time must be timezone aware")
        snapshot_at = member_snapshot_generated_at.astimezone(UTC)
        now = self._now()
        if snapshot_at > now + timedelta(minutes=2) or now - snapshot_at > timedelta(days=8):
            raise TrustCoreError("member snapshot is outside the accepted poll window")
        eligible_subjects, expected_snapshot_digest = self._member_snapshot_values(
            release_version=release.release_version,
            notice_version=release.notice_version,
            at=snapshot_at,
        )
        if (
            member_snapshot_digest != expected_snapshot_digest
            or subject_id not in eligible_subjects
        ):
            raise TrustCoreError("member subject was not eligible in the frozen snapshot")
        if requested_expires_at.tzinfo is None or requested_expires_at.utcoffset() is None:
            raise TrustCoreError("member presentation expiry must be timezone aware")
        expires_at = min(requested_expires_at.astimezone(UTC), now + timedelta(minutes=10))
        if expires_at <= now:
            raise TrustCoreError("member presentation expiry must be in the future")
        pairwise = _token(
            "pws",
            hmac.digest(
                self._pairwise_secret,
                (
                    f"campaign-member|{subject_id}|{audience}|"
                    f"{determination_version_id}|{manifest_hash}"
                ).encode(),
                "sha256",
            ),
        )
        receipt = self._publish("member.presented", "issued", "member_presentation")
        unsigned = MemberPresentation(
            presentation_id=self._id("mpr"),
            issuer=self.issuer,
            audience=audience,
            pairwise_subject=pairwise,
            determination_version_id=determination_version_id,
            manifest_hash=manifest_hash,
            member_snapshot_digest=member_snapshot_digest,
            release_version=release.release_version,
            verification_basis="self_asserted",
            issued_at=now,
            expires_at=expires_at,
            receipt_id=receipt.receipt_id,
            proof={},
        )
        return replace(unsigned, proof=self.signer.sign(unsigned.signing_payload())), receipt

    def _member_snapshot_values(
        self,
        *,
        release_version: str,
        notice_version: str,
        at: datetime,
    ) -> tuple[tuple[str, ...], str]:
        eligible_subjects = tuple(
            sorted(
                subject.subject_id
                for subject in self._subjects.values()
                if subject.created_at <= at
                and (subject.deleted_at is None or subject.deleted_at > at)
                and any(
                    consent.subject_id == subject.subject_id
                    and consent.granted_at <= at
                    and (consent.withdrawn_at is None or consent.withdrawn_at > at)
                    and "kyn_campaign_member_ballot" in consent.purposes
                    for consent in self._consents.values()
                )
            )
        )
        opaque_members = tuple(
            _token(
                "mem",
                hmac.digest(
                    self._pairwise_secret,
                    f"member-snapshot|{release_version}|{subject_id}".encode(),
                    "sha256",
                ),
            )
            for subject_id in eligible_subjects
        )
        digest = (
            "sha256:"
            + hashlib.sha256(
                "|".join((release_version, notice_version, *opaque_members)).encode()
            ).hexdigest()
        )
        return eligible_subjects, digest

    def public_events(self) -> tuple[PublicEvent, ...]:
        return tuple(self._events)

    def public_receipts(self) -> tuple[Receipt, ...]:
        return tuple(self._receipts)

    def participant_key_for_subject(self, subject_id: str) -> str:
        """Private service-adapter lookup; never expose through a relying-party API."""

        participant_key = self._require_subject(subject_id).participant_key
        if participant_key is None:
            raise TrustCoreError("subject key binding has been deleted")
        return participant_key

    def participant_key_for_authority(self, authority_grant_id: str) -> str:
        grant = self._require_authority_grant(authority_grant_id)
        return self.participant_key_for_subject(grant.holder_subject_id)

    def participant_key_for_credential(self, credential_id: str) -> str:
        try:
            credential = self._credentials[credential_id]
        except KeyError as exc:
            raise TrustCoreError("credential is unknown") from exc
        request = self._require_request(credential.request_id)
        return self.participant_key_for_subject(request.subject_id)

    def participant_key_for_request(self, request_id: str) -> str:
        request = self._require_request(request_id)
        return self.participant_key_for_subject(request.subject_id)

    def participant_key_for_invitation(self, invitation_id: str) -> str:
        try:
            invitation = self._invitations[invitation_id]
        except KeyError as exc:
            raise TrustCoreError("attestor invitation is unknown") from exc
        return self.participant_key_for_subject(invitation.verifier_subject_id)

    def participant_key_for_challenge_party(self, challenge_id: str) -> str:
        challenge = self._require_challenge(challenge_id)
        attestation = self._require_attestation(challenge.attestation_id)
        return self.participant_key_for_subject(attestation.verifier_subject_id)

    def participant_key_for_privacy_request(self, privacy_request_id: str) -> str:
        try:
            request = self._privacy_requests[privacy_request_id]
        except KeyError as exc:
            raise TrustCoreError("privacy request is unknown") from exc
        return self.participant_key_for_subject(request.subject_id)

    def credential_status_by_id(self, credential_id: str) -> CredentialStatus:
        try:
            credential = self._credentials[credential_id]
        except KeyError as exc:
            raise TrustCoreError("credential is unknown") from exc
        return self.credential_status(credential.status_reference)

    def public_receipt(self, receipt_id: str) -> Receipt:
        matches = [item for item in self._receipts if item.receipt_id == receipt_id]
        if len(matches) != 1:
            raise TrustCoreError("receipt is unavailable")
        return matches[0]

    def export_snapshot(self) -> dict[str, Any]:
        """Export private state for an encrypted, access-controlled durable store."""

        records: list[object] = [
            *self._subjects.values(),
            *self._operator_releases.values(),
            *self._consents.values(),
            *self._recovery_commitments.values(),
            *self._recovery_cases.values(),
            *self._privacy_requests.values(),
            *self._claims.values(),
            *self._requests.values(),
            *self._grants.values(),
            *self._bootstrap_authorities.values(),
            *self._authority_grants.values(),
            *self._authority_promotions.values(),
            *self._invitations.values(),
            *self._introductions.values(),
            *self._attestations.values(),
            *self._audits.values(),
            *self._challenges.values(),
            *self._credentials.values(),
            *self._events,
            *self._receipts,
        ]
        return {
            "snapshot_version": 2,
            "issuer": self.issuer,
            "policy_profile": self.policy.profile_id,
            "counters": dict(self._counters),
            "records": [to_record(record) for record in records],  # type: ignore[arg-type]
        }

    def restore_snapshot(self, snapshot: dict[str, Any]) -> None:
        """Restore a validated snapshot into a fresh TrustCore instance."""

        if snapshot.get("snapshot_version") not in {1, 2}:
            raise TrustCoreError("snapshot version is unsupported")
        if snapshot.get("issuer") != self.issuer:
            raise TrustCoreError("snapshot issuer does not match this service")
        if snapshot.get("policy_profile") != self.policy.profile_id:
            raise TrustCoreError("snapshot policy profile does not match this service")
        if any(
            (
                self._subjects,
                self._claims,
                self._requests,
                self._grants,
                self._authority_grants,
                self._credentials,
                self._events,
                self._receipts,
            )
        ):
            raise TrustCoreError("snapshot restore requires a fresh TrustCore")
        counters = snapshot.get("counters")
        records = snapshot.get("records")
        if not isinstance(counters, dict) or not isinstance(records, list):
            raise TrustCoreError("snapshot structure is invalid")
        if not all(
            isinstance(key, str) and isinstance(value, int) for key, value in counters.items()
        ):
            raise TrustCoreError("snapshot counters are invalid")
        self._counters = dict(counters)
        for payload in records:
            if not isinstance(payload, dict):
                raise TrustCoreError("snapshot record is invalid")
            migrated = dict(payload)
            if snapshot.get("snapshot_version") == 1:
                if migrated.get("record_type") == "subject":
                    migrated.setdefault("deleted_at", None)
                elif migrated.get("record_type") == "challenge":
                    migrated.setdefault("challenger_subject_id", None)
            record = from_record(migrated)
            self._restore_record(record)

    def _restore_record(self, record: object) -> None:  # noqa: PLR0912
        if isinstance(record, Subject):
            self._subjects[record.subject_id] = record
        elif isinstance(record, OperatorRelease):
            self._operator_releases[record.release_id] = record
        elif isinstance(record, ConsentRecord):
            self._consents[record.consent_id] = record
        elif isinstance(record, RecoveryCommitment):
            self._recovery_commitments[record.recovery_commitment_id] = record
        elif isinstance(record, RecoveryCase):
            self._recovery_cases[record.recovery_case_id] = record
        elif isinstance(record, PrivacyRequest):
            self._privacy_requests[record.privacy_request_id] = record
        elif isinstance(record, ClaimDefinition):
            key = (record.claim_type, record.definition_version, record.policy_version)
            self._claims[key] = record
        elif isinstance(record, ClaimRequest):
            self._requests[record.request_id] = record
        elif isinstance(record, VerifierGrant):
            self._grants[record.grant_id] = record
        elif isinstance(record, BootstrapAuthority):
            self._bootstrap_authorities[record.bootstrap_id] = record
        elif isinstance(record, AuthorityGrant):
            self._authority_grants[record.authority_grant_id] = record
        elif isinstance(record, AuthorityPromotion):
            self._authority_promotions[record.promotion_id] = record
        elif isinstance(record, AttestorInvitation):
            self._invitations[record.invitation_id] = record
        elif isinstance(record, Introduction):
            self._introductions[record.introduction_id] = record
        elif isinstance(record, Attestation):
            self._attestations[record.attestation_id] = record
        elif isinstance(record, Audit):
            self._audits[record.audit_id] = record
        elif isinstance(record, Challenge):
            self._challenges[record.challenge_id] = record
        elif isinstance(record, Credential):
            self._credentials[record.credential_id] = record
            self._credential_by_request[record.request_id] = record.credential_id
        elif isinstance(record, PublicEvent):
            self._events.append(record)
        elif isinstance(record, Receipt):
            self._receipts.append(record)
        else:
            raise TrustCoreError(f"snapshot record is unsupported: {type(record).__name__}")

    def _active_attestations(self, request_id: str, now: datetime) -> list[Attestation]:
        return [
            item
            for item in self._attestations.values()
            if item.request_id == request_id
            and item.state is AttestationState.ACTIVE
            and item.expires_at > now
            and self._grant_is_active(item.grant_id, now)
        ]

    def _recalculate(self, request_id: str) -> Credential | None:
        request = self._require_request(request_id)
        now = self._now()
        active = self._active_attestations(request_id, now)
        existing_id = self._credential_by_request.get(request_id)
        if not active and existing_id is None:
            return None
        passed_audits = {
            audit.attestation_id
            for audit in self._audits.values()
            if audit.state is AuditState.PASSED
        }
        definition = request.definition
        required_attestations = (
            definition.minimum_attestations
            if definition.minimum_attestations is not None
            else self.policy.required_attestations
        )
        required_paths = (
            definition.minimum_independent_paths
            if definition.minimum_independent_paths is not None
            else self.policy.required_independent_paths
        )
        required_audits = (
            definition.minimum_passed_audits
            if definition.minimum_passed_audits is not None
            else self.policy.required_passed_audits
        )
        bases = {item.verification_basis for item in active}
        if {item.attestation_id for item in active} & passed_audits:
            bases.add(VerificationBasis.AUDIT_CORROBORATED)
        qualifies = (
            len(active) >= required_attestations
            and len({item.independence_path for item in active}) >= required_paths
            and len({item.attestation_id for item in active} & passed_audits) >= required_audits
            and definition.required_verification_bases <= bases
        )
        if existing_id is None:
            credential_id = self._id("crd")
            issued_at = now
            status_reference = f"{self.issuer}/status/{credential_id}"
            prior_state = None
        else:
            existing = self._credentials[existing_id]
            credential_id = existing.credential_id
            issued_at = existing.issued_at
            status_reference = existing.status_reference
            prior_state = existing.state
        if qualifies:
            state = CredentialState.ACTIVE
        elif prior_state in {CredentialState.ACTIVE, CredentialState.REVOKED} or not active:
            state = CredentialState.REVOKED
        else:
            state = CredentialState.PROVISIONAL
        dependency_ids = tuple(sorted(item.attestation_id for item in active))
        if (
            existing_id is not None
            and existing.state is state
            and existing.dependency_attestation_ids == dependency_ids
            and existing.verification_bases == tuple(sorted(bases, key=lambda item: item.value))
        ):
            return existing
        credential = Credential(
            credential_id=credential_id,
            request_id=request_id,
            definition=request.definition,
            state=state,
            dependency_attestation_ids=dependency_ids,
            issued_at=issued_at,
            expires_at=issued_at + self.policy.credential_ttl,
            status_reference=status_reference,
            updated_at=now,
            verification_bases=tuple(sorted(bases, key=lambda item: item.value)),
        )
        self._credentials[credential_id] = credential
        self._credential_by_request[request_id] = credential_id
        return credential

    def _require_subject(self, subject_id: str) -> Subject:
        try:
            return self._subjects[subject_id]
        except KeyError as exc:
            raise TrustCoreError("subject is unknown") from exc

    def _require_active_release(self) -> None:
        if self.policy.enforce_release:
            self.current_operator_release()

    def _has_active_consent(self, subject_id: str, purpose: str) -> bool:
        return any(
            item.subject_id == subject_id and item.withdrawn_at is None and purpose in item.purposes
            for item in self._consents.values()
        )

    def _invalidate_subject_state(self, subject_id: str, *, reason: str) -> tuple[Credential, ...]:
        affected_requests = {
            item.request_id for item in self._requests.values() if item.subject_id == subject_id
        }
        for attestation_id, attestation in tuple(self._attestations.items()):
            if (
                attestation.verifier_subject_id == subject_id
                or attestation.request_id in affected_requests
            ):
                self._attestations[attestation_id] = replace(
                    attestation,
                    state=AttestationState.INVALIDATED,
                    invalidation_reason=reason,
                )
                affected_requests.add(attestation.request_id)
        for grant_id, grant in tuple(self._authority_grants.items()):
            if grant.holder_subject_id == subject_id and grant.revoked_at is None:
                self._authority_grants[grant_id] = replace(
                    grant, revoked_at=self._now(), revocation_reason=reason
                )
        return tuple(
            credential
            for request_id in sorted(affected_requests)
            if (credential := self._recalculate(request_id)) is not None
        )

    def _require_request(self, request_id: str) -> ClaimRequest:
        try:
            return self._requests[request_id]
        except KeyError as exc:
            raise TrustCoreError("claim request is unknown") from exc

    def _require_attestation(self, attestation_id: str) -> Attestation:
        try:
            return self._attestations[attestation_id]
        except KeyError as exc:
            raise TrustCoreError("attestation is unknown") from exc

    def _require_challenge(self, challenge_id: str) -> Challenge:
        try:
            return self._challenges[challenge_id]
        except KeyError as exc:
            raise TrustCoreError("challenge is unknown") from exc

    def _require_authority_grant(self, authority_grant_id: str) -> AuthorityGrant:
        try:
            return self._authority_grants[authority_grant_id]
        except KeyError as exc:
            raise TrustCoreError("authority grant is unknown") from exc

    @staticmethod
    def _scope_subset(requested: frozenset[str], permitted: frozenset[str]) -> bool:
        return "*" in permitted or requested <= permitted

    def _grant_is_active(self, grant_id: str, now: datetime) -> bool:
        if grant := self._grants.get(grant_id):
            return grant.revoked_at is None and grant.expires_at > now
        if authority := self._authority_grants.get(grant_id):
            return authority.revoked_at is None and authority.expires_at > now
        return False

    def _resolve_attestation_authority(
        self,
        *,
        grant_id: str,
        request: ClaimRequest,
        method_class: str,
        now: datetime,
    ) -> tuple[str, datetime, int | None]:
        if authority_grant := self._authority_grants.get(grant_id):
            consumed = self._consume_authority(
                authority_grant.authority_grant_id,
                AuthorityCapability.ATTEST_CLAIM,
                claim_type=request.definition.claim_type,
                method_class=method_class,
            )
            return consumed.holder_subject_id, consumed.expires_at, consumed.usage_cap
        if legacy_grant := self._grants.get(grant_id):
            if legacy_grant.revoked_at is not None or legacy_grant.expires_at <= now:
                raise TrustCoreError("verifier grant is not active")
            if request.definition.claim_type != legacy_grant.claim_type:
                raise TrustCoreError("verifier grant does not cover the requested claim")
            if method_class not in legacy_grant.method_classes:
                raise TrustCoreError("verifier grant does not cover the selected method")
            return (
                legacy_grant.verifier_subject_id,
                legacy_grant.expires_at,
                legacy_grant.attestation_cap,
            )
        raise TrustCoreError("verifier authority is unknown")

    def _resolve_independence_path(
        self,
        *,
        request: ClaimRequest,
        verifier_subject_id: str,
        verification_basis: VerificationBasis,
        introduction_id: str | None,
        fallback: str | None,
        now: datetime,
    ) -> str:
        if not (
            self.policy.enforce_authority and verification_basis is VerificationBasis.PEER_ATTESTED
        ):
            if fallback is None:
                raise TrustCoreError("attestation requires an independence path")
            return fallback
        if introduction_id is None:
            raise TrustCoreError("live peer attestation requires an introduction")
        try:
            introduction = self._introductions[introduction_id]
        except KeyError as exc:
            raise TrustCoreError("live peer attestation requires an introduction") from exc
        if (
            introduction.request_id != request.request_id
            or introduction.invited_verifier_subject_id != verifier_subject_id
        ):
            raise TrustCoreError("introduction does not match the invitation")
        if introduction.expires_at <= now:
            raise TrustCoreError("introduction has expired")
        return _token(
            "path",
            hmac.digest(
                self._receipt_secret,
                f"{request.request_id}|{introduction.introducer_subject_id}".encode(),
                "sha256",
            ),
        )

    def _consume_authority(
        self,
        authority_grant_id: str,
        capability: AuthorityCapability,
        *,
        claim_type: str | None = None,
        method_class: str | None = None,
    ) -> AuthorityGrant:
        grant = self._validate_authority(
            authority_grant_id,
            capability,
            claim_type=claim_type,
            method_class=method_class,
        )
        updated = replace(grant, used_count=grant.used_count + 1)
        self._authority_grants[authority_grant_id] = updated
        return updated

    def _validate_authority(
        self,
        authority_grant_id: str,
        capability: AuthorityCapability,
        *,
        claim_type: str | None = None,
        method_class: str | None = None,
    ) -> AuthorityGrant:
        grant = self._require_authority_grant(authority_grant_id)
        now = self._now()
        if grant.revoked_at is not None or grant.expires_at <= now:
            raise TrustCoreError("authority grant is not active")
        if capability not in grant.capabilities:
            raise TrustCoreError("authority grant lacks the required capability")
        if claim_type is not None and not self._scope_subset(
            frozenset({claim_type}), grant.claim_types
        ):
            raise TrustCoreError("authority grant does not cover the claim")
        if method_class is not None and not self._scope_subset(
            frozenset({method_class}), grant.method_classes
        ):
            raise TrustCoreError("authority grant does not cover the method")
        if grant.usage_cap is not None and grant.used_count >= grant.usage_cap:
            raise TrustCoreError("authority usage cap has been reached")
        return grant

    def _authorize_if_required(
        self,
        authority_grant_id: str | None,
        capability: AuthorityCapability,
        *,
        claim_type: str | None = None,
        method_class: str | None = None,
    ) -> None:
        if authority_grant_id is None:
            if self.policy.enforce_authority:
                raise TrustCoreError("active policy requires explicit authority")
            return
        self._consume_authority(
            authority_grant_id,
            capability,
            claim_type=claim_type,
            method_class=method_class,
        )
