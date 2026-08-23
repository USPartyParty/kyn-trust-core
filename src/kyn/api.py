"""Authenticated KYN-000C public-beta API routes."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from kyn.auth import VerifiedAction, authorize_participant_action, verify_bootstrap_token
from kyn.contracts import TrustRecord, to_record
from kyn.models import (
    AppealDecision,
    AuditBasis,
    AuthorityBasis,
    AuthorityCapability,
    AuthorityTier,
    ChallengeDecision,
    ClaimDefinition,
    JsonValue,
    PrivacyRequestKind,
    StoragePosture,
    VerificationBasis,
)
from kyn.persistence import DurableTrustService, ExecutionResult, TransitionResult
from kyn.service import TrustCore

router = APIRouter()
bootstrap_bearer = HTTPBearer(auto_error=False)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ActionProof(StrictModel):
    nonce: str = Field(pattern=r"^[A-Za-z0-9_-]{16,120}$")
    issued_at: datetime
    signature: str = Field(pattern=r"^[A-Za-z0-9_-]{86}$")


class ProofOnlyInput(StrictModel):
    proof: ActionProof


class CreateSubjectInput(StrictModel):
    participant_key: str = Field(pattern=r"^did:key:ed25519:[A-Za-z0-9_-]{43}$")
    proof: ActionProof


class ActivateBootstrapInput(CreateSubjectInput):
    public_label: str = Field(min_length=1, max_length=120)
    designation_reference: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    expires_at: datetime
    release_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    notice_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    terms_url: str = Field(pattern=r"^https://")
    privacy_url: str = Field(pattern=r"^https://")
    operator_contact: str = Field(min_length=3, max_length=200)
    storage_posture: StoragePosture
    backup_evidence_reference: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    sensitive_evidence_enabled: bool = False


class RegisterClaimInput(StrictModel):
    actor_authority_grant_id: str = Field(pattern=r"^agr_[A-Za-z0-9_-]{8,120}$")
    claim_type: str = Field(pattern=r"^[a-z][a-z0-9_]{2,119}$")
    definition_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    policy_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    method_class: str = Field(pattern=r"^[a-z][a-z0-9_]{2,79}$")
    allowed_verification_bases: frozenset[VerificationBasis]
    required_verification_bases: frozenset[VerificationBasis] = frozenset()
    minimum_attestations: int = Field(ge=0)
    minimum_independent_paths: int = Field(ge=0)
    minimum_passed_audits: int = Field(ge=0)
    proof: ActionProof


class RequestClaimInput(StrictModel):
    subject_id: str = Field(pattern=r"^sub_[A-Za-z0-9_-]{8,120}$")
    claim_type: str = Field(pattern=r"^[a-z][a-z0-9_]{2,119}$")
    definition_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    policy_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    proof: ActionProof


class BootstrapAttestationInput(StrictModel):
    authority_grant_id: str = Field(pattern=r"^agr_[A-Za-z0-9_-]{8,120}$")
    expires_at: datetime
    proof: ActionProof


class GrantAuthorityInput(StrictModel):
    actor_authority_grant_id: str = Field(pattern=r"^agr_[A-Za-z0-9_-]{8,120}$")
    holder_subject_id: str = Field(pattern=r"^sub_[A-Za-z0-9_-]{8,120}$")
    capabilities: frozenset[AuthorityCapability]
    claim_types: frozenset[str]
    method_classes: frozenset[str]
    tier: AuthorityTier
    expires_at: datetime
    usage_cap: int | None = Field(default=None, ge=1)
    can_delegate: bool = False
    max_delegation_depth: int = Field(ge=0, le=16)
    public_accountability_label: str | None = Field(default=None, max_length=120)
    proof: ActionProof


class RevokeAuthorityInput(StrictModel):
    actor_authority_grant_id: str = Field(pattern=r"^agr_[A-Za-z0-9_-]{8,120}$")
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{2,99}$")
    proof: ActionProof


class PromoteAuthorityInput(StrictModel):
    actor_authority_grant_id: str = Field(pattern=r"^agr_[A-Za-z0-9_-]{8,120}$")
    source_authority_grant_ids: tuple[str, ...] = Field(min_length=1)
    resulting_tier: AuthorityTier
    capabilities: frozenset[AuthorityCapability]
    expires_at: datetime
    public_accountability_label: str | None = Field(default=None, max_length=120)
    proof: ActionProof


class PresentCredentialInput(StrictModel):
    audience: str = Field(min_length=1, max_length=200)
    proof: ActionProof


class ConsentInput(StrictModel):
    notice_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    purposes: frozenset[str] = Field(min_length=1)
    proof: ActionProof


class OperatorReleaseInput(StrictModel):
    actor_authority_grant_id: str = Field(pattern=r"^agr_[A-Za-z0-9_-]{8,120}$")
    release_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    notice_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    terms_url: str = Field(pattern=r"^https://")
    privacy_url: str = Field(pattern=r"^https://")
    operator_contact: str = Field(min_length=3, max_length=200)
    storage_posture: StoragePosture
    backup_evidence_reference: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    sensitive_evidence_enabled: bool = False
    proof: ActionProof


class RecoveryCommitmentInput(StrictModel):
    commitment: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    proof: ActionProof


class RecoveryRequestInput(StrictModel):
    subject_id: str = Field(pattern=r"^sub_[A-Za-z0-9_-]{8,120}$")
    replacement_participant_key: str = Field(pattern=r"^did:key:ed25519:[A-Za-z0-9_-]{43}$")
    recovery_secret: str = Field(min_length=32, max_length=256)
    proof: ActionProof


class RecoveryDecisionInput(StrictModel):
    actor_authority_grant_id: str = Field(pattern=r"^agr_[A-Za-z0-9_-]{8,120}$")
    approve: bool
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{2,99}$")
    proof: ActionProof


class PrivacyRequestInput(StrictModel):
    kind: PrivacyRequestKind
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{2,99}$")
    proof: ActionProof


class PrivacyDecisionInput(StrictModel):
    actor_authority_grant_id: str = Field(pattern=r"^agr_[A-Za-z0-9_-]{8,120}$")
    approve: bool
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{2,99}$")
    proof: ActionProof


class InviteAttestorInput(StrictModel):
    request_id: str = Field(pattern=r"^clm_[A-Za-z0-9_-]{8,120}$")
    verifier_subject_id: str = Field(pattern=r"^sub_[A-Za-z0-9_-]{8,120}$")
    expires_at: datetime
    proof: ActionProof


class IntroduceAttestorInput(StrictModel):
    actor_authority_grant_id: str = Field(pattern=r"^agr_[A-Za-z0-9_-]{8,120}$")
    request_id: str = Field(pattern=r"^clm_[A-Za-z0-9_-]{8,120}$")
    introducer_subject_id: str = Field(pattern=r"^sub_[A-Za-z0-9_-]{8,120}$")
    invited_verifier_subject_id: str = Field(pattern=r"^sub_[A-Za-z0-9_-]{8,120}$")
    expires_at: datetime
    proof: ActionProof


class IssueAttestationInput(StrictModel):
    invitation_id: str = Field(pattern=r"^inv_[A-Za-z0-9_-]{8,120}$")
    authority_grant_id: str = Field(pattern=r"^agr_[A-Za-z0-9_-]{8,120}$")
    introduction_id: str = Field(pattern=r"^int_[A-Za-z0-9_-]{8,120}$")
    method_class: str = Field(pattern=r"^[a-z][a-z0-9_]{2,79}$")
    expires_at: datetime
    verification_basis: VerificationBasis = VerificationBasis.PEER_ATTESTED
    proof: ActionProof


class SelectAuditInput(StrictModel):
    actor_authority_grant_id: str = Field(pattern=r"^agr_[A-Za-z0-9_-]{8,120}$")
    attestation_id: str = Field(pattern=r"^att_[A-Za-z0-9_-]{8,120}$")
    basis: AuditBasis
    selection_seed: str = Field(min_length=16, max_length=200)
    proof: ActionProof


class DecideAuditInput(StrictModel):
    actor_authority_grant_id: str = Field(pattern=r"^agr_[A-Za-z0-9_-]{8,120}$")
    passed: bool
    proof: ActionProof


class OpenChallengeInput(StrictModel):
    challenger_subject_id: str = Field(pattern=r"^sub_[A-Za-z0-9_-]{8,120}$")
    attestation_id: str = Field(pattern=r"^att_[A-Za-z0-9_-]{8,120}$")
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{2,99}$")
    proof: ActionProof


class ChallengeResponseInput(StrictModel):
    response_code: str = Field(pattern=r"^[a-z][a-z0-9_]{2,99}$")
    proof: ActionProof


class ChallengeDecisionInput(StrictModel):
    actor_authority_grant_id: str = Field(pattern=r"^agr_[A-Za-z0-9_-]{8,120}$")
    decision: ChallengeDecision
    proof: ActionProof


class AppealInput(StrictModel):
    appeal_reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{2,99}$")
    proof: ActionProof


class AppealDecisionInput(StrictModel):
    actor_authority_grant_id: str = Field(pattern=r"^agr_[A-Za-z0-9_-]{8,120}$")
    decision: AppealDecision
    proof: ActionProof


def _service(request: Request) -> DurableTrustService:
    return cast(DurableTrustService, request.app.state.trust_service)


def _body(model: StrictModel) -> dict[str, JsonValue]:
    dumped = cast(dict[str, JsonValue], model.model_dump(mode="json", exclude={"proof"}))

    def normalize(value: JsonValue) -> JsonValue:
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items()}
        if isinstance(value, list):
            normalized = [normalize(item) for item in value]
            return sorted(
                normalized,
                key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
            )
        return value

    return cast(dict[str, JsonValue], normalize(dumped))


async def _authorize(
    request: Request,
    *,
    participant_key: str,
    operation: str,
    model: StrictModel,
    signed_body: dict[str, JsonValue] | None = None,
) -> VerifiedAction:
    proof = cast(ActionProof, model.proof)  # type: ignore[attr-defined]
    return authorize_participant_action(
        participant_key=participant_key,
        operation=operation,
        nonce=proof.nonce,
        issued_at=proof.issued_at,
        signature=proof.signature,
        body=signed_body or _body(model),
        now=datetime.now(tz=UTC),
        maximum_skew=timedelta(seconds=request.app.state.action_clock_skew_seconds),
    )


def _response(result: ExecutionResult) -> dict[str, Any]:
    return {
        "records": [to_record(record) for record in result.records],
        "receipt": to_record(result.receipt),
        "replayed": result.replayed,
    }


@router.post("/subjects", status_code=status.HTTP_201_CREATED)
async def create_subject(payload: CreateSubjectInput, request: Request) -> dict[str, Any]:
    operation = "subject.create"
    action = await _authorize(
        request,
        participant_key=payload.participant_key,
        operation=operation,
        model=payload,
    )

    def transition(core: TrustCore) -> TransitionResult:
        subject, receipt = core.create_subject(payload.participant_key)
        return TransitionResult(records=(cast(TrustRecord, subject),), receipt=receipt)

    result = await _service(request).execute(
        command_id=action.command_id,
        operation=operation,
        actor_reference=action.actor_reference,
        request_payload=_body(payload),
        transition=transition,
    )
    return _response(result)


@router.post("/bootstrap/activate", status_code=status.HTTP_201_CREATED)
async def activate_bootstrap(
    payload: ActivateBootstrapInput,
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bootstrap_bearer)],
) -> dict[str, Any]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    verify_bootstrap_token(
        supplied=credentials.credentials,
        expected=request.app.state.bootstrap_token,
    )
    operation = "authority.bootstrap_activate"
    action = await _authorize(
        request,
        participant_key=payload.participant_key,
        operation=operation,
        model=payload,
    )

    def transition(core: TrustCore) -> TransitionResult:
        subject, _ = core.create_subject(payload.participant_key, bootstrap=True)
        bootstrap, grant, _ = core.bootstrap_authority(
            authority_subject_id=subject.subject_id,
            public_label=payload.public_label,
            designation_reference=payload.designation_reference,
            policy_version=payload.policy_version,
            expires_at=payload.expires_at,
        )
        release, receipt = core.register_operator_release(
            actor_authority_grant_id=grant.authority_grant_id,
            release_version=payload.release_version,
            notice_version=payload.notice_version,
            terms_url=payload.terms_url,
            privacy_url=payload.privacy_url,
            operator_contact=payload.operator_contact,
            storage_posture=payload.storage_posture,
            backup_evidence_reference=payload.backup_evidence_reference,
            sensitive_evidence_enabled=payload.sensitive_evidence_enabled,
        )
        return TransitionResult(
            records=tuple(cast(TrustRecord, item) for item in (subject, bootstrap, grant, release)),
            receipt=receipt,
        )

    result = await _service(request).execute(
        command_id=action.command_id,
        operation=operation,
        actor_reference=action.actor_reference,
        request_payload=_body(payload),
        transition=transition,
    )
    return _response(result)


@router.post("/claim-definitions", status_code=status.HTTP_201_CREATED)
async def register_claim(payload: RegisterClaimInput, request: Request) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    participant_key = core.participant_key_for_authority(payload.actor_authority_grant_id)
    operation = "claim_definition.register"
    action = await _authorize(
        request, participant_key=participant_key, operation=operation, model=payload
    )
    definition = ClaimDefinition(
        claim_type=payload.claim_type,
        definition_version=payload.definition_version,
        policy_version=payload.policy_version,
        method_class=payload.method_class,
        allowed_verification_bases=payload.allowed_verification_bases,
        required_verification_bases=payload.required_verification_bases,
        minimum_attestations=payload.minimum_attestations,
        minimum_independent_paths=payload.minimum_independent_paths,
        minimum_passed_audits=payload.minimum_passed_audits,
    )

    def transition(state: TrustCore) -> TransitionResult:
        receipt = state.register_claim(
            definition,
            actor_authority_grant_id=payload.actor_authority_grant_id,
        )
        return TransitionResult(records=(cast(TrustRecord, definition),), receipt=receipt)

    result = await service.execute(
        command_id=action.command_id,
        operation=operation,
        actor_reference=action.actor_reference,
        request_payload=_body(payload),
        transition=transition,
    )
    return _response(result)


@router.post("/claim-requests", status_code=status.HTTP_201_CREATED)
async def request_claim(payload: RequestClaimInput, request: Request) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    participant_key = core.participant_key_for_subject(payload.subject_id)
    operation = "claim.request"
    action = await _authorize(
        request, participant_key=participant_key, operation=operation, model=payload
    )

    def transition(state: TrustCore) -> TransitionResult:
        claim_request, receipt = state.request_claim(
            subject_id=payload.subject_id,
            claim_type=payload.claim_type,
            definition_version=payload.definition_version,
            policy_version=payload.policy_version,
        )
        return TransitionResult(records=(cast(TrustRecord, claim_request),), receipt=receipt)

    result = await service.execute(
        command_id=action.command_id,
        operation=operation,
        actor_reference=action.actor_reference,
        request_payload=_body(payload),
        transition=transition,
    )
    return _response(result)


@router.post("/claim-requests/{request_id}/bootstrap-attestation")
async def issue_bootstrap_attestation(
    request_id: str, payload: BootstrapAttestationInput, request: Request
) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    participant_key = core.participant_key_for_authority(payload.authority_grant_id)
    operation = "attestation.bootstrap_issue"
    signed_body: dict[str, JsonValue] = {"request_id": request_id, **_body(payload)}
    action = await _authorize(
        request,
        participant_key=participant_key,
        operation=operation,
        model=payload,
        signed_body=signed_body,
    )

    def transition(state: TrustCore) -> TransitionResult:
        attestation, credential, receipt = state.issue_bootstrap_attestation(
            request_id=request_id,
            authority_grant_id=payload.authority_grant_id,
            expires_at=payload.expires_at,
        )
        return TransitionResult(
            records=tuple(cast(TrustRecord, item) for item in (attestation, credential)),
            receipt=receipt,
        )

    result = await service.execute(
        command_id=action.command_id,
        operation=operation,
        actor_reference=action.actor_reference,
        request_payload=signed_body,
        transition=transition,
    )
    return _response(result)


@router.post("/authority-grants", status_code=status.HTTP_201_CREATED)
async def grant_authority(payload: GrantAuthorityInput, request: Request) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    participant_key = core.participant_key_for_authority(payload.actor_authority_grant_id)
    operation = "authority.grant"
    action = await _authorize(
        request, participant_key=participant_key, operation=operation, model=payload
    )

    def transition(state: TrustCore) -> TransitionResult:
        grant, receipt = state.grant_authority(
            actor_authority_grant_id=payload.actor_authority_grant_id,
            holder_subject_id=payload.holder_subject_id,
            capabilities=payload.capabilities,
            claim_types=payload.claim_types,
            method_classes=payload.method_classes,
            tier=payload.tier,
            expires_at=payload.expires_at,
            usage_cap=payload.usage_cap,
            can_delegate=payload.can_delegate,
            max_delegation_depth=payload.max_delegation_depth,
            public_accountability_label=payload.public_accountability_label,
            basis=AuthorityBasis.DELEGATED,
        )
        return TransitionResult(records=(cast(TrustRecord, grant),), receipt=receipt)

    result = await service.execute(
        command_id=action.command_id,
        operation=operation,
        actor_reference=action.actor_reference,
        request_payload=_body(payload),
        transition=transition,
    )
    return _response(result)


@router.post("/authority-grants/{authority_grant_id}/revocation")
async def revoke_authority(
    authority_grant_id: str, payload: RevokeAuthorityInput, request: Request
) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    participant_key = core.participant_key_for_authority(payload.actor_authority_grant_id)
    operation = "authority.revoke"
    signed_body = {"authority_grant_id": authority_grant_id, **_body(payload)}
    action = await _authorize(
        request,
        participant_key=participant_key,
        operation=operation,
        model=payload,
        signed_body=signed_body,
    )

    def transition(state: TrustCore) -> TransitionResult:
        revoked, credentials, receipt = state.revoke_authority(
            actor_authority_grant_id=payload.actor_authority_grant_id,
            authority_grant_id=authority_grant_id,
            reason_code=payload.reason_code,
        )
        records = tuple(cast(TrustRecord, item) for item in (*revoked, *credentials))
        return TransitionResult(records=records, receipt=receipt)

    result = await service.execute(
        command_id=action.command_id,
        operation=operation,
        actor_reference=action.actor_reference,
        request_payload=signed_body,
        transition=transition,
    )
    return _response(result)


@router.post("/authority-promotions", status_code=status.HTTP_201_CREATED)
async def promote_authority(payload: PromoteAuthorityInput, request: Request) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    participant_key = core.participant_key_for_authority(payload.actor_authority_grant_id)
    operation = "authority.promote"
    action = await _authorize(
        request, participant_key=participant_key, operation=operation, model=payload
    )

    def transition(state: TrustCore) -> TransitionResult:
        promotion, grant, receipt = state.promote_authority(
            actor_authority_grant_id=payload.actor_authority_grant_id,
            source_authority_grant_ids=payload.source_authority_grant_ids,
            resulting_tier=payload.resulting_tier,
            capabilities=payload.capabilities,
            expires_at=payload.expires_at,
            public_accountability_label=payload.public_accountability_label,
        )
        return TransitionResult(
            records=tuple(cast(TrustRecord, item) for item in (promotion, grant)),
            receipt=receipt,
        )

    result = await service.execute(
        command_id=action.command_id,
        operation=operation,
        actor_reference=action.actor_reference,
        request_payload=_body(payload),
        transition=transition,
    )
    return _response(result)


@router.post("/subjects/{subject_id}/consents", status_code=status.HTTP_201_CREATED)
async def accept_consent(
    subject_id: str, payload: ConsentInput, request: Request
) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    operation = "consent.accept"
    signed_body = {"subject_id": subject_id, **_body(payload)}
    action = await _authorize(
        request,
        participant_key=core.participant_key_for_subject(subject_id),
        operation=operation,
        model=payload,
        signed_body=signed_body,
    )

    def transition(state: TrustCore) -> TransitionResult:
        consent, receipt = state.accept_consent(
            subject_id=subject_id,
            notice_version=payload.notice_version,
            purposes=payload.purposes,
        )
        return TransitionResult(records=(cast(TrustRecord, consent),), receipt=receipt)

    return _response(
        await service.execute(
            command_id=action.command_id,
            operation=operation,
            actor_reference=action.actor_reference,
            request_payload=signed_body,
            transition=transition,
        )
    )


@router.post("/subjects/{subject_id}/recovery-commitments", status_code=status.HTTP_201_CREATED)
async def register_recovery_commitment(
    subject_id: str, payload: RecoveryCommitmentInput, request: Request
) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    operation = "recovery.commitment_register"
    signed_body = {"subject_id": subject_id, **_body(payload)}
    action = await _authorize(
        request,
        participant_key=core.participant_key_for_subject(subject_id),
        operation=operation,
        model=payload,
        signed_body=signed_body,
    )

    def transition(state: TrustCore) -> TransitionResult:
        record, receipt = state.register_recovery_commitment(
            subject_id=subject_id, commitment=payload.commitment
        )
        return TransitionResult(records=(cast(TrustRecord, record),), receipt=receipt)

    return _response(
        await service.execute(
            command_id=action.command_id,
            operation=operation,
            actor_reference=action.actor_reference,
            request_payload=signed_body,
            transition=transition,
        )
    )


@router.post("/recovery-cases", status_code=status.HTTP_201_CREATED)
async def request_recovery(payload: RecoveryRequestInput, request: Request) -> dict[str, Any]:
    service = _service(request)
    operation = "recovery.request"
    action = await _authorize(
        request,
        participant_key=payload.replacement_participant_key,
        operation=operation,
        model=payload,
    )

    def transition(state: TrustCore) -> TransitionResult:
        case, receipt = state.request_recovery(
            subject_id=payload.subject_id,
            replacement_participant_key=payload.replacement_participant_key,
            recovery_secret=payload.recovery_secret,
        )
        return TransitionResult(records=(cast(TrustRecord, case),), receipt=receipt)

    return _response(
        await service.execute(
            command_id=action.command_id,
            operation=operation,
            actor_reference=action.actor_reference,
            request_payload=_body(payload),
            transition=transition,
        )
    )


@router.post("/recovery-cases/{recovery_case_id}/decision")
async def decide_recovery(
    recovery_case_id: str, payload: RecoveryDecisionInput, request: Request
) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    operation = "recovery.decide"
    signed_body = {"recovery_case_id": recovery_case_id, **_body(payload)}
    action = await _authorize(
        request,
        participant_key=core.participant_key_for_authority(payload.actor_authority_grant_id),
        operation=operation,
        model=payload,
        signed_body=signed_body,
    )

    def transition(state: TrustCore) -> TransitionResult:
        case, subject, receipt = state.decide_recovery(
            recovery_case_id=recovery_case_id,
            actor_authority_grant_id=payload.actor_authority_grant_id,
            approve=payload.approve,
            reason_code=payload.reason_code,
        )
        return TransitionResult(
            records=(cast(TrustRecord, case), cast(TrustRecord, subject)), receipt=receipt
        )

    return _response(
        await service.execute(
            command_id=action.command_id,
            operation=operation,
            actor_reference=action.actor_reference,
            request_payload=signed_body,
            transition=transition,
        )
    )


@router.post("/subjects/{subject_id}/privacy-requests", status_code=status.HTTP_201_CREATED)
async def open_privacy_request(
    subject_id: str, payload: PrivacyRequestInput, request: Request
) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    operation = "privacy.request"
    signed_body = {"subject_id": subject_id, **_body(payload)}
    action = await _authorize(
        request,
        participant_key=core.participant_key_for_subject(subject_id),
        operation=operation,
        model=payload,
        signed_body=signed_body,
    )

    def transition(state: TrustCore) -> TransitionResult:
        privacy_request, receipt = state.open_privacy_request(
            subject_id=subject_id, kind=payload.kind, reason_code=payload.reason_code
        )
        return TransitionResult(records=(cast(TrustRecord, privacy_request),), receipt=receipt)

    return _response(
        await service.execute(
            command_id=action.command_id,
            operation=operation,
            actor_reference=action.actor_reference,
            request_payload=signed_body,
            transition=transition,
        )
    )


@router.post("/privacy-requests/{privacy_request_id}/decision")
async def process_privacy_request(
    privacy_request_id: str, payload: PrivacyDecisionInput, request: Request
) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    operation = "privacy.process"
    signed_body = {"privacy_request_id": privacy_request_id, **_body(payload)}
    action = await _authorize(
        request,
        participant_key=core.participant_key_for_authority(payload.actor_authority_grant_id),
        operation=operation,
        model=payload,
        signed_body=signed_body,
    )

    def transition(state: TrustCore) -> TransitionResult:
        privacy_request, credentials, receipt = state.process_privacy_request(
            privacy_request_id=privacy_request_id,
            actor_authority_grant_id=payload.actor_authority_grant_id,
            approve=payload.approve,
            reason_code=payload.reason_code,
        )
        return TransitionResult(
            records=tuple(cast(TrustRecord, item) for item in (privacy_request, *credentials)),
            receipt=receipt,
        )

    return _response(
        await service.execute(
            command_id=action.command_id,
            operation=operation,
            actor_reference=action.actor_reference,
            request_payload=signed_body,
            transition=transition,
        )
    )


@router.post("/privacy-requests/{privacy_request_id}/export")
async def export_privacy_request(
    privacy_request_id: str, payload: ProofOnlyInput, request: Request
) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    operation = "privacy.export"
    signed_body: dict[str, JsonValue] = {"privacy_request_id": privacy_request_id}
    action = await _authorize(
        request,
        participant_key=core.participant_key_for_privacy_request(privacy_request_id),
        operation=operation,
        model=payload,
        signed_body=signed_body,
    )

    def transition(state: TrustCore) -> TransitionResult:
        export, receipt = state.privacy_export(privacy_request_id)
        return TransitionResult(records=(), receipt=receipt, response_payload=export)

    result = await service.execute(
        command_id=action.command_id,
        operation=operation,
        actor_reference=action.actor_reference,
        request_payload=signed_body,
        transition=transition,
    )
    return {
        "export": result.response_payload,
        "receipt": to_record(result.receipt),
        "replayed": result.replayed,
    }


@router.post("/attestor-invitations", status_code=status.HTTP_201_CREATED)
async def invite_attestor(payload: InviteAttestorInput, request: Request) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    operation = "attestor.invite"
    action = await _authorize(
        request,
        participant_key=core.participant_key_for_request(payload.request_id),
        operation=operation,
        model=payload,
    )

    def transition(state: TrustCore) -> TransitionResult:
        invitation, receipt = state.invite_attestor(
            request_id=payload.request_id,
            verifier_subject_id=payload.verifier_subject_id,
            expires_at=payload.expires_at,
        )
        return TransitionResult(records=(cast(TrustRecord, invitation),), receipt=receipt)

    return _response(
        await service.execute(
            command_id=action.command_id,
            operation=operation,
            actor_reference=action.actor_reference,
            request_payload=_body(payload),
            transition=transition,
        )
    )


@router.post("/introductions", status_code=status.HTTP_201_CREATED)
async def introduce_attestor(payload: IntroduceAttestorInput, request: Request) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    operation = "attestor.introduce"
    action = await _authorize(
        request,
        participant_key=core.participant_key_for_authority(payload.actor_authority_grant_id),
        operation=operation,
        model=payload,
    )

    def transition(state: TrustCore) -> TransitionResult:
        introduction, receipt = state.introduce_attestor(
            request_id=payload.request_id,
            introducer_subject_id=payload.introducer_subject_id,
            invited_verifier_subject_id=payload.invited_verifier_subject_id,
            expires_at=payload.expires_at,
            actor_authority_grant_id=payload.actor_authority_grant_id,
        )
        return TransitionResult(records=(cast(TrustRecord, introduction),), receipt=receipt)

    return _response(
        await service.execute(
            command_id=action.command_id,
            operation=operation,
            actor_reference=action.actor_reference,
            request_payload=_body(payload),
            transition=transition,
        )
    )


@router.post("/attestations", status_code=status.HTTP_201_CREATED)
async def issue_attestation(payload: IssueAttestationInput, request: Request) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    operation = "attestation.issue"
    action = await _authorize(
        request,
        participant_key=core.participant_key_for_invitation(payload.invitation_id),
        operation=operation,
        model=payload,
    )

    def transition(state: TrustCore) -> TransitionResult:
        attestation, credential, receipt = state.issue_attestation(
            invitation_id=payload.invitation_id,
            grant_id=payload.authority_grant_id,
            introduction_id=payload.introduction_id,
            method_class=payload.method_class,
            expires_at=payload.expires_at,
            verification_basis=payload.verification_basis,
        )
        return TransitionResult(
            records=tuple(cast(TrustRecord, item) for item in (attestation, credential)),
            receipt=receipt,
        )

    return _response(
        await service.execute(
            command_id=action.command_id,
            operation=operation,
            actor_reference=action.actor_reference,
            request_payload=_body(payload),
            transition=transition,
        )
    )


@router.post("/audits", status_code=status.HTTP_201_CREATED)
async def select_audit(payload: SelectAuditInput, request: Request) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    operation = "audit.select"
    action = await _authorize(
        request,
        participant_key=core.participant_key_for_authority(payload.actor_authority_grant_id),
        operation=operation,
        model=payload,
    )

    def transition(state: TrustCore) -> TransitionResult:
        audit, receipt = state.select_audit(
            attestation_id=payload.attestation_id,
            basis=payload.basis,
            selection_seed=payload.selection_seed,
            actor_authority_grant_id=payload.actor_authority_grant_id,
        )
        return TransitionResult(records=(cast(TrustRecord, audit),), receipt=receipt)

    return _response(
        await service.execute(
            command_id=action.command_id,
            operation=operation,
            actor_reference=action.actor_reference,
            request_payload=_body(payload),
            transition=transition,
        )
    )


@router.post("/audits/{audit_id}/decision")
async def decide_audit(
    audit_id: str, payload: DecideAuditInput, request: Request
) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    operation = "audit.decide"
    signed_body = {"audit_id": audit_id, **_body(payload)}
    action = await _authorize(
        request,
        participant_key=core.participant_key_for_authority(payload.actor_authority_grant_id),
        operation=operation,
        model=payload,
        signed_body=signed_body,
    )

    def transition(state: TrustCore) -> TransitionResult:
        audit, credential, receipt = state.decide_audit(
            audit_id=audit_id,
            passed=payload.passed,
            actor_authority_grant_id=payload.actor_authority_grant_id,
        )
        return TransitionResult(
            records=tuple(cast(TrustRecord, item) for item in (audit, credential)),
            receipt=receipt,
        )

    return _response(
        await service.execute(
            command_id=action.command_id,
            operation=operation,
            actor_reference=action.actor_reference,
            request_payload=signed_body,
            transition=transition,
        )
    )


@router.post("/challenges", status_code=status.HTTP_201_CREATED)
async def open_challenge(payload: OpenChallengeInput, request: Request) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    operation = "challenge.open"
    action = await _authorize(
        request,
        participant_key=core.participant_key_for_subject(payload.challenger_subject_id),
        operation=operation,
        model=payload,
    )

    def transition(state: TrustCore) -> TransitionResult:
        challenge, receipt = state.open_challenge(
            attestation_id=payload.attestation_id,
            reason_code=payload.reason_code,
            challenger_subject_id=payload.challenger_subject_id,
        )
        return TransitionResult(records=(cast(TrustRecord, challenge),), receipt=receipt)

    return _response(
        await service.execute(
            command_id=action.command_id,
            operation=operation,
            actor_reference=action.actor_reference,
            request_payload=_body(payload),
            transition=transition,
        )
    )


@router.post("/challenges/{challenge_id}/response")
async def respond_to_challenge(
    challenge_id: str, payload: ChallengeResponseInput, request: Request
) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    operation = "challenge.respond"
    signed_body = {"challenge_id": challenge_id, **_body(payload)}
    action = await _authorize(
        request,
        participant_key=core.participant_key_for_challenge_party(challenge_id),
        operation=operation,
        model=payload,
        signed_body=signed_body,
    )

    def transition(state: TrustCore) -> TransitionResult:
        challenge, receipt = state.respond_to_challenge(
            challenge_id=challenge_id, response_code=payload.response_code
        )
        return TransitionResult(records=(cast(TrustRecord, challenge),), receipt=receipt)

    return _response(
        await service.execute(
            command_id=action.command_id,
            operation=operation,
            actor_reference=action.actor_reference,
            request_payload=signed_body,
            transition=transition,
        )
    )


@router.post("/challenges/{challenge_id}/decision")
async def decide_challenge(
    challenge_id: str, payload: ChallengeDecisionInput, request: Request
) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    operation = "challenge.decide"
    signed_body = {"challenge_id": challenge_id, **_body(payload)}
    action = await _authorize(
        request,
        participant_key=core.participant_key_for_authority(payload.actor_authority_grant_id),
        operation=operation,
        model=payload,
        signed_body=signed_body,
    )

    def transition(state: TrustCore) -> TransitionResult:
        challenge, credential, receipt = state.decide_challenge(
            challenge_id=challenge_id,
            decision=payload.decision,
            actor_authority_grant_id=payload.actor_authority_grant_id,
        )
        return TransitionResult(
            records=tuple(cast(TrustRecord, item) for item in (challenge, credential)),
            receipt=receipt,
        )

    return _response(
        await service.execute(
            command_id=action.command_id,
            operation=operation,
            actor_reference=action.actor_reference,
            request_payload=signed_body,
            transition=transition,
        )
    )


@router.post("/challenges/{challenge_id}/appeal")
async def appeal_challenge(
    challenge_id: str, payload: AppealInput, request: Request
) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    operation = "challenge.appeal"
    signed_body = {"challenge_id": challenge_id, **_body(payload)}
    action = await _authorize(
        request,
        participant_key=core.participant_key_for_challenge_party(challenge_id),
        operation=operation,
        model=payload,
        signed_body=signed_body,
    )

    def transition(state: TrustCore) -> TransitionResult:
        challenge, receipt = state.appeal_challenge(
            challenge_id=challenge_id,
            appeal_reason_code=payload.appeal_reason_code,
        )
        return TransitionResult(records=(cast(TrustRecord, challenge),), receipt=receipt)

    return _response(
        await service.execute(
            command_id=action.command_id,
            operation=operation,
            actor_reference=action.actor_reference,
            request_payload=signed_body,
            transition=transition,
        )
    )


@router.post("/challenges/{challenge_id}/appeal-decision")
async def decide_appeal(
    challenge_id: str, payload: AppealDecisionInput, request: Request
) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    operation = "appeal.decide"
    signed_body = {"challenge_id": challenge_id, **_body(payload)}
    action = await _authorize(
        request,
        participant_key=core.participant_key_for_authority(payload.actor_authority_grant_id),
        operation=operation,
        model=payload,
        signed_body=signed_body,
    )

    def transition(state: TrustCore) -> TransitionResult:
        challenge, credential, receipt = state.decide_appeal(
            challenge_id=challenge_id,
            decision=payload.decision,
            actor_authority_grant_id=payload.actor_authority_grant_id,
        )
        return TransitionResult(
            records=tuple(cast(TrustRecord, item) for item in (challenge, credential)),
            receipt=receipt,
        )

    return _response(
        await service.execute(
            command_id=action.command_id,
            operation=operation,
            actor_reference=action.actor_reference,
            request_payload=signed_body,
            transition=transition,
        )
    )


@router.post("/credentials/{credential_id}/presentations", status_code=status.HTTP_201_CREATED)
async def present_credential(
    credential_id: str, payload: PresentCredentialInput, request: Request
) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    participant_key = core.participant_key_for_credential(credential_id)
    operation = "credential.present"
    signed_body = {"credential_id": credential_id, **_body(payload)}
    action = await _authorize(
        request,
        participant_key=participant_key,
        operation=operation,
        model=payload,
        signed_body=signed_body,
    )

    def transition(state: TrustCore) -> TransitionResult:
        presentation, receipt = state.present_credential(
            credential_id=credential_id,
            audience=payload.audience,
        )
        return TransitionResult(
            records=(),
            receipt=receipt,
            response_payload=cast(dict[str, object], presentation.as_dict()),
        )

    result = await service.execute(
        command_id=action.command_id,
        operation=operation,
        actor_reference=action.actor_reference,
        request_payload=signed_body,
        transition=transition,
    )
    if result.response_payload is None:
        raise RuntimeError("stored presentation response is unavailable")
    return {
        "presentation": result.response_payload,
        "receipt": to_record(result.receipt),
        "replayed": result.replayed,
    }


@router.get("/status/{credential_id}")
async def credential_status(credential_id: str, request: Request) -> dict[str, Any]:
    core = await _service(request).load_core()
    return to_record(core.credential_status_by_id(credential_id))


@router.get("/operator-release")
async def operator_release(request: Request) -> dict[str, Any]:
    core = await _service(request).load_core()
    release = core.current_operator_release(required=False)
    if release is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
    return to_record(release)


@router.post("/operator-releases", status_code=status.HTTP_201_CREATED)
async def register_operator_release(
    payload: OperatorReleaseInput, request: Request
) -> dict[str, Any]:
    service = _service(request)
    core = await service.load_core()
    operation = "operator_release.register"
    action = await _authorize(
        request,
        participant_key=core.participant_key_for_authority(payload.actor_authority_grant_id),
        operation=operation,
        model=payload,
    )

    def transition(state: TrustCore) -> TransitionResult:
        release, receipt = state.register_operator_release(
            actor_authority_grant_id=payload.actor_authority_grant_id,
            release_version=payload.release_version,
            notice_version=payload.notice_version,
            terms_url=payload.terms_url,
            privacy_url=payload.privacy_url,
            operator_contact=payload.operator_contact,
            storage_posture=payload.storage_posture,
            backup_evidence_reference=payload.backup_evidence_reference,
            sensitive_evidence_enabled=payload.sensitive_evidence_enabled,
        )
        return TransitionResult(records=(cast(TrustRecord, release),), receipt=receipt)

    return _response(
        await service.execute(
            command_id=action.command_id,
            operation=operation,
            actor_reference=action.actor_reference,
            request_payload=_body(payload),
            transition=transition,
        )
    )


@router.get("/events")
async def public_events(request: Request) -> list[dict[str, Any]]:
    core = await _service(request).load_core()
    return [to_record(item) for item in core.public_events()]


@router.get("/receipts/{receipt_id}")
async def public_receipt(receipt_id: str, request: Request) -> dict[str, Any]:
    core = await _service(request).load_core()
    return to_record(core.public_receipt(receipt_id))
