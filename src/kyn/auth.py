"""Participant proof-of-key-control and replay-key helpers."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from kyn.crypto import verify_participant_action
from kyn.models import JsonValue


class ActionAuthorizationError(ValueError):
    pass


MIN_NONCE_LENGTH = 16
MAX_NONCE_LENGTH = 120


@dataclass(frozen=True, slots=True)
class VerifiedAction:
    command_id: str
    actor_reference: str


def authorize_participant_action(
    *,
    participant_key: str,
    operation: str,
    nonce: str,
    issued_at: datetime,
    signature: str,
    body: dict[str, JsonValue],
    now: datetime,
    maximum_skew: timedelta,
) -> VerifiedAction:
    if issued_at.tzinfo is None or issued_at.utcoffset() is None:
        raise ActionAuthorizationError("action timestamp must be timezone aware")
    if not MIN_NONCE_LENGTH <= len(nonce) <= MAX_NONCE_LENGTH or not all(
        character.isalnum() or character in "_-" for character in nonce
    ):
        raise ActionAuthorizationError("action nonce is invalid")
    normalized_issued_at = issued_at.astimezone(UTC)
    if abs(now.astimezone(UTC) - normalized_issued_at) > maximum_skew:
        raise ActionAuthorizationError("action timestamp is outside the accepted window")
    issued_at_text = normalized_issued_at.isoformat().replace("+00:00", "Z")
    if not verify_participant_action(
        participant_key=participant_key,
        operation=operation,
        nonce=nonce,
        issued_at=issued_at_text,
        body=body,
        signature=signature,
    ):
        raise ActionAuthorizationError("participant action proof is invalid")
    actor_digest = hashlib.sha256(participant_key.encode()).hexdigest()
    command_digest = hashlib.sha256(f"{participant_key}|{nonce}".encode()).hexdigest()
    return VerifiedAction(
        command_id=f"cmd_{command_digest}",
        actor_reference=f"key_sha256:{actor_digest}",
    )


def verify_bootstrap_token(*, supplied: str, expected: bytes) -> None:
    if not supplied or not hmac.compare_digest(supplied.encode(), expected):
        raise ActionAuthorizationError("bootstrap authentication failed")
