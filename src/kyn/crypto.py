"""Small deterministic proof helpers for the synthetic KYN boundary."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from kyn.models import JsonValue

ED25519_SEED_BYTES = 32


def canonical_json(payload: dict[str, JsonValue]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True, slots=True)
class Ed25519Signer:
    key_id: str
    _private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls, key_id: str) -> Ed25519Signer:
        return cls(key_id=key_id, _private_key=Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, key_id: str, seed: bytes) -> Ed25519Signer:
        if len(seed) != ED25519_SEED_BYTES:
            raise ValueError("Ed25519 seed must be exactly 32 bytes")
        return cls(key_id=key_id, _private_key=Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def public_key(self) -> str:
        raw = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return _encode(raw)

    @property
    def participant_key(self) -> str:
        """KYN's constrained Ed25519 did:key representation for beta clients."""

        return f"did:key:ed25519:{self.public_key}"

    def sign(self, payload: dict[str, JsonValue]) -> dict[str, str]:
        return {
            "type": "Ed25519Signature2020",
            "key_id": self.key_id,
            "value": _encode(self._private_key.sign(canonical_json(payload))),
        }

    def sign_action(
        self,
        *,
        operation: str,
        nonce: str,
        issued_at: str,
        body: dict[str, JsonValue],
    ) -> str:
        payload = action_signing_payload(
            operation=operation,
            nonce=nonce,
            issued_at=issued_at,
            body=body,
        )
        return _encode(self._private_key.sign(canonical_json(payload)))


@dataclass(frozen=True, slots=True)
class Ed25519Verifier:
    key_id: str
    public_key: str

    def verify(self, payload: dict[str, JsonValue], proof: dict[str, str]) -> bool:
        if proof.get("type") != "Ed25519Signature2020" or proof.get("key_id") != self.key_id:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(_decode(self.public_key)).verify(
                _decode(proof["value"]), canonical_json(payload)
            )
        except (InvalidSignature, KeyError, TypeError, ValueError):
            return False
        return True


def action_signing_payload(
    *, operation: str, nonce: str, issued_at: str, body: dict[str, JsonValue]
) -> dict[str, JsonValue]:
    return {
        "operation": operation,
        "nonce": nonce,
        "issued_at": issued_at,
        "body_sha256": f"sha256:{hashlib.sha256(canonical_json(body)).hexdigest()}",
    }


def verify_participant_action(
    *,
    participant_key: str,
    operation: str,
    nonce: str,
    issued_at: str,
    body: dict[str, JsonValue],
    signature: str,
) -> bool:
    prefix = "did:key:ed25519:"
    if not participant_key.startswith(prefix):
        return False
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            _decode(participant_key.removeprefix(prefix))
        )
        payload = action_signing_payload(
            operation=operation,
            nonce=nonce,
            issued_at=issued_at,
            body=body,
        )
        public_key.verify(_decode(signature), canonical_json(payload))
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True
