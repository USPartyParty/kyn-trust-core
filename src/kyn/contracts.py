"""Exact JSON-record serialization for the public KYN Trust Core contracts."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from enum import Enum
from types import UnionType
from typing import Any, cast, get_args, get_origin, get_type_hints

from kyn.models import (
    Attestation,
    AttestorInvitation,
    Audit,
    AuthorityGrant,
    AuthorityPromotion,
    BootstrapAuthority,
    Challenge,
    ClaimDefinition,
    ClaimRequest,
    ConsentRecord,
    Credential,
    CredentialStatus,
    Introduction,
    OperatorRelease,
    PrivacyRequest,
    PublicEvent,
    Receipt,
    RecoveryCase,
    RecoveryCommitment,
    Subject,
    VerifierGrant,
)

type TrustRecord = (
    Attestation
    | AttestorInvitation
    | AuthorityGrant
    | AuthorityPromotion
    | Audit
    | BootstrapAuthority
    | Challenge
    | ClaimDefinition
    | ClaimRequest
    | ConsentRecord
    | Credential
    | CredentialStatus
    | Introduction
    | OperatorRelease
    | PrivacyRequest
    | PublicEvent
    | Receipt
    | RecoveryCase
    | RecoveryCommitment
    | Subject
    | VerifierGrant
)

RECORD_TYPES: dict[type[object], str] = {
    Attestation: "attestation",
    AttestorInvitation: "attestor_invitation",
    AuthorityGrant: "authority_grant",
    AuthorityPromotion: "authority_promotion",
    Audit: "audit",
    BootstrapAuthority: "bootstrap_authority",
    Challenge: "challenge",
    ClaimDefinition: "claim_definition",
    ClaimRequest: "claim_request",
    ConsentRecord: "consent_record",
    Credential: "credential",
    CredentialStatus: "credential_status",
    Introduction: "introduction",
    OperatorRelease: "operator_release",
    PrivacyRequest: "privacy_request",
    PublicEvent: "public_event",
    Receipt: "receipt",
    RecoveryCase: "recovery_case",
    RecoveryCommitment: "recovery_commitment",
    Subject: "subject",
    VerifierGrant: "verifier_grant",
}
RECORD_CLASSES = {record_type: record_class for record_class, record_type in RECORD_TYPES.items()}


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (frozenset, list, set, tuple)):
        return [_json_value(item) for item in value]
    return value


def to_record(record: TrustRecord) -> dict[str, Any]:
    """Serialize one private or public record to its strict versioned JSON shape."""

    try:
        record_type = RECORD_TYPES[type(record)]
    except KeyError as exc:
        raise TypeError(f"unsupported KYN contract record: {type(record).__name__}") from exc
    payload = _json_value(asdict(record))
    if not isinstance(payload, dict):
        raise TypeError("KYN record serialization must produce an object")
    if definition := payload.pop("definition", None):
        payload["claim"] = {"record_type": "claim_definition", **definition}
    return {"record_type": record_type, **payload}


def _from_json(annotation: Any, value: Any) -> Any:  # noqa: PLR0911
    if value is None:
        return None
    if annotation is datetime:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        return annotation(value)
    origin = get_origin(annotation)
    arguments = get_args(annotation)
    if origin is UnionType:
        non_none = [item for item in arguments if item is not type(None)]
        if len(non_none) == 1:
            return _from_json(non_none[0], value)
    if origin is frozenset:
        return frozenset(_from_json(arguments[0], item) for item in value)
    if origin is tuple:
        return tuple(_from_json(arguments[0], item) for item in value)
    if origin is list:
        return [_from_json(arguments[0], item) for item in value]
    if origin is dict or annotation == dict[str, Any]:
        return dict(value)
    return value


def from_record(payload: dict[str, Any]) -> TrustRecord:
    """Restore one exact contract record for a durable state snapshot."""

    record_type = payload.get("record_type")
    if not isinstance(record_type, str) or record_type not in RECORD_CLASSES:
        raise ValueError("unknown KYN record type")
    record_class = RECORD_CLASSES[record_type]
    values = {key: value for key, value in payload.items() if key != "record_type"}
    if "claim" in values:
        claim = values.pop("claim")
        if not isinstance(claim, dict):
            raise TypeError("nested KYN claim must be an object")
        definition = from_record(claim)
        if not isinstance(definition, ClaimDefinition):
            raise TypeError("nested KYN claim must be a claim definition")
        values["definition"] = definition
    hints = get_type_hints(record_class)
    if set(values) != set(hints):
        raise ValueError("KYN record fields do not match the exact contract")
    converted = {key: _from_json(hints[key], value) for key, value in values.items()}
    return cast(TrustRecord, record_class(**converted))
