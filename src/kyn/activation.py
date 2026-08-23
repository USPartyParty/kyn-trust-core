"""Trusted, explicit KC bootstrap activation client."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import secrets
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pydantic import BaseModel, ConfigDict, Field, model_validator

from kyn.config import read_secret_file
from kyn.crypto import Ed25519Signer, canonical_json, verify_participant_action
from kyn.models import JsonValue, StoragePosture

KEY_ASSOCIATED_DATA = b"KYN KC activation key v1"
MINIMUM_PASSPHRASE_LENGTH = 16
PARTICIPANT_SEED_BYTES = 32
BOOTSTRAP_RECORD_TYPES = frozenset(
    {"subject", "bootstrap_authority", "authority_grant", "operator_release"}
)


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < MINIMUM_PASSPHRASE_LENGTH:
        raise ValueError("activation-key passphrase must contain at least 16 characters")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode())


def _private_parent(path: Path) -> None:
    parent = path.parent
    if parent.exists():
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError("activation output parent is unsafe")
    else:
        parent.mkdir(mode=0o700, parents=True)
        parent.chmod(0o700)
    if parent.stat().st_mode & 0o077:
        raise ValueError("activation output parent permissions are too broad")


class ActivationDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")

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

    @model_validator(mode="after")
    def accepted_bootstrap_boundary(self) -> ActivationDraft:
        if self.public_label != "KC Streich":
            raise ValueError("activation draft must use the accepted KC public label")
        if self.sensitive_evidence_enabled:
            raise ValueError("KYN-000C activation cannot enable sensitive evidence")
        if "@" not in self.operator_contact:
            raise ValueError("activation draft requires a public operator contact")
        return self


class PreparedActivation(BaseModel):
    """Portable signed request; contains no private key or bootstrap token."""

    model_config = ConfigDict(extra="forbid")

    prepared_version: int = Field(default=1, ge=1, le=1)
    activation_body_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    request: dict[str, Any]
    prepared_at: datetime


def create_encrypted_key(path: Path, passphrase: str, *, seed: bytes | None = None) -> str:
    if path.exists():
        raise FileExistsError("refusing to replace an activation key file")
    _private_parent(path)
    seed = seed or secrets.token_bytes(PARTICIPANT_SEED_BYTES)
    if len(seed) != PARTICIPANT_SEED_BYTES:
        raise ValueError("participant seed must be exactly 32 bytes")
    signer = Ed25519Signer.from_seed("kc-kyn-participant", seed)
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_derive_key(passphrase, salt)).encrypt(nonce, seed, KEY_ASSOCIATED_DATA)
    payload = {
        "key_file_version": 1,
        "participant_key": signer.participant_key,
        "kdf": {"name": "scrypt", "n": 32768, "r": 8, "p": 1, "salt": _encode(salt)},
        "cipher": {"name": "aes-256-gcm", "nonce": _encode(nonce)},
        "ciphertext": _encode(ciphertext),
    }
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    return signer.participant_key


def load_encrypted_key(path: Path, passphrase: str) -> Ed25519Signer:
    if path.is_symlink() or not path.is_file():
        raise ValueError("activation key file is unsafe")
    if path.stat().st_mode & 0o077:
        raise ValueError("activation key file permissions are too broad")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if (
        payload.get("key_file_version") != 1
        or payload.get("kdf", {}).get("name") != "scrypt"
        or payload.get("cipher", {}).get("name") != "aes-256-gcm"
    ):
        raise ValueError("activation key file format is unsupported")
    salt = _decode(payload["kdf"]["salt"])
    nonce = _decode(payload["cipher"]["nonce"])
    seed = AESGCM(_derive_key(passphrase, salt)).decrypt(
        nonce, _decode(payload["ciphertext"]), KEY_ASSOCIATED_DATA
    )
    signer = Ed25519Signer.from_seed("kc-kyn-participant", seed)
    if not secrets.compare_digest(signer.participant_key, payload["participant_key"]):
        raise ValueError("activation key public binding does not match")
    return signer


def activation_body(draft: ActivationDraft, signer: Ed25519Signer) -> dict[str, JsonValue]:
    return {
        "participant_key": signer.participant_key,
        **draft.model_dump(mode="json"),
    }


def body_digest(body: dict[str, JsonValue]) -> str:
    return f"sha256:{hashlib.sha256(canonical_json(body)).hexdigest()}"


def _activation_body_from_request(request: dict[str, Any]) -> dict[str, JsonValue]:
    proof = request.get("proof")
    if not isinstance(proof, dict) or set(proof) != {"nonce", "issued_at", "signature"}:
        raise ValueError("prepared activation proof is invalid")
    body = {key: value for key, value in request.items() if key != "proof"}
    participant_key = body.pop("participant_key", None)
    if not isinstance(participant_key, str) or not participant_key.startswith("did:key:ed25519:"):
        raise ValueError("prepared activation participant key is invalid")
    draft = ActivationDraft.model_validate(body)
    return {"participant_key": participant_key, **draft.model_dump(mode="json")}


def _validate_prepared(prepared: PreparedActivation, *, now: datetime) -> dict[str, Any]:
    body = _activation_body_from_request(prepared.request)
    digest = body_digest(body)
    if not secrets.compare_digest(digest, prepared.activation_body_digest):
        raise ValueError("prepared activation body digest does not match")
    draft = ActivationDraft.model_validate(
        {key: value for key, value in body.items() if key != "participant_key"}
    )
    if draft.expires_at <= now:
        raise ValueError("KC authority expiry must be in the future")
    proof = prepared.request["proof"]
    if not isinstance(proof, dict) or not all(
        isinstance(proof.get(field), str) for field in ("nonce", "issued_at", "signature")
    ):
        raise ValueError("prepared activation proof is invalid")
    if not verify_participant_action(
        participant_key=str(body["participant_key"]),
        operation="authority.bootstrap_activate",
        nonce=proof["nonce"],
        issued_at=proof["issued_at"],
        body=body,
        signature=proof["signature"],
    ):
        raise ValueError("prepared activation signature is invalid")
    return prepared.request


def prepare_activation(
    *,
    draft: ActivationDraft,
    signer: Ed25519Signer,
    confirmation: str,
    now: datetime | None = None,
) -> PreparedActivation:
    current = now or datetime.now(tz=UTC)
    if draft.expires_at <= current:
        raise ValueError("KC authority expiry must be in the future")
    body = activation_body(draft, signer)
    digest = body_digest(body)
    expected_confirmation = f"ACTIVATE {digest[-12:]}"
    if not secrets.compare_digest(confirmation, expected_confirmation):
        raise ValueError(f"activation confirmation must equal {expected_confirmation}")
    issued_at = current.isoformat().replace("+00:00", "Z")
    nonce = secrets.token_urlsafe(18)
    signature = signer.sign_action(
        operation="authority.bootstrap_activate",
        nonce=nonce,
        issued_at=issued_at,
        body=body,
    )
    return PreparedActivation(
        activation_body_digest=digest,
        request={
            **body,
            "proof": {"nonce": nonce, "issued_at": issued_at, "signature": signature},
        },
        prepared_at=current,
    )


def _write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError("refusing to replace activation evidence")
    _private_parent(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(evidence, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _post_activation(api_url: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    base = api_url.rstrip("/")
    parsed = urllib.parse.urlsplit(base)
    local = parsed.hostname in {"localhost", "127.0.0.1"}
    if parsed.scheme != "https" and not (local and parsed.scheme == "http"):
        raise ValueError("activation API must use HTTPS or local loopback HTTP")
    request = urllib.request.Request(  # noqa: S310
        f"{base}/v1/bootstrap/activate",
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
            result = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"KYN activation failed with HTTP {exc.code}: {detail}") from exc
    if not isinstance(result, dict):
        raise RuntimeError("KYN activation returned an invalid response")
    return result


def _validate_activation_response(
    response: dict[str, Any], *, prepared: PreparedActivation
) -> None:
    records = response.get("records")
    receipt = response.get("receipt")
    if not isinstance(records, list) or len(records) != len(BOOTSTRAP_RECORD_TYPES):
        raise RuntimeError("KYN activation response did not contain four bootstrap records")
    by_type = {
        item.get("record_type"): item
        for item in records
        if isinstance(item, dict) and isinstance(item.get("record_type"), str)
    }
    if set(by_type) != BOOTSTRAP_RECORD_TYPES:
        raise RuntimeError("KYN activation response record types are invalid")
    body = _activation_body_from_request(prepared.request)
    if by_type["subject"].get("participant_key") != body["participant_key"]:
        raise RuntimeError("KYN activation response changed the KC participant key")
    if by_type["bootstrap_authority"].get("public_label") != body["public_label"]:
        raise RuntimeError("KYN activation response changed the KC public label")
    release = by_type["operator_release"]
    expected_release = {
        "release_version": body["release_version"],
        "notice_version": body["notice_version"],
        "terms_url": body["terms_url"],
        "privacy_url": body["privacy_url"],
        "operator_contact": body["operator_contact"],
        "storage_posture": body["storage_posture"],
        "backup_evidence_reference": body["backup_evidence_reference"],
        "sensitive_evidence_enabled": False,
    }
    if any(release.get(key) != value for key, value in expected_release.items()):
        raise RuntimeError("KYN activation response does not match the accepted release")
    if not isinstance(receipt, dict) or receipt.get("record_type") != "receipt":
        raise RuntimeError("KYN activation response did not contain a receipt")


def submit_prepared_activation(
    *,
    api_url: str,
    prepared: PreparedActivation,
    bootstrap_token_file: Path,
    evidence_path: Path,
    confirmation: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    if evidence_path.exists():
        raise FileExistsError("refusing activation because the evidence path already exists")
    current = now or datetime.now(tz=UTC)
    request_payload = _validate_prepared(prepared, now=current)
    expected_confirmation = f"SUBMIT {prepared.activation_body_digest[-12:]}"
    if not secrets.compare_digest(confirmation, expected_confirmation):
        raise ValueError(f"submission confirmation must equal {expected_confirmation}")
    token = read_secret_file(bootstrap_token_file).decode("utf-8")
    response = _post_activation(api_url, token, request_payload)
    _validate_activation_response(response, prepared=prepared)
    evidence = {
        "evidence_version": 1,
        "operation": "authority.bootstrap_activate",
        "api_url": api_url.rstrip("/"),
        "activation_body_digest": prepared.activation_body_digest,
        "request": request_payload,
        "response": response,
        "recorded_at": datetime.now(tz=UTC).isoformat().replace("+00:00", "Z"),
    }
    _write_evidence(evidence_path, evidence)
    return response


def activate(
    *,
    api_url: str,
    draft: ActivationDraft,
    signer: Ed25519Signer,
    bootstrap_token_file: Path,
    evidence_path: Path,
    confirmation: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = now or datetime.now(tz=UTC)
    prepared = prepare_activation(
        draft=draft,
        signer=signer,
        confirmation=confirmation,
        now=current,
    )
    return submit_prepared_activation(
        api_url=api_url,
        prepared=prepared,
        bootstrap_token_file=bootstrap_token_file,
        evidence_path=evidence_path,
        confirmation=f"SUBMIT {prepared.activation_body_digest[-12:]}",
        now=current,
    )


def _passphrase(confirm: bool = False) -> str:
    first = getpass.getpass("Activation-key passphrase: ")
    if confirm and not secrets.compare_digest(
        first, getpass.getpass("Confirm activation-key passphrase: ")
    ):
        raise ValueError("activation-key passphrases do not match")
    return first


def _draft(path: Path) -> ActivationDraft:
    return ActivationDraft.model_validate_json(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Trusted KC KYN activation client")
    commands = parser.add_subparsers(dest="command", required=True)
    key_init = commands.add_parser("key-init", help="create an encrypted KC participant key")
    key_init.add_argument("--output", type=Path, required=True)
    inspect = commands.add_parser("inspect", help="display the public activation payload digest")
    inspect.add_argument("--key-file", type=Path, required=True)
    inspect.add_argument("--draft", type=Path, required=True)
    activate_command = commands.add_parser("activate", help="perform one-time KC activation")
    activate_command.add_argument("--api-url", required=True)
    activate_command.add_argument("--key-file", type=Path, required=True)
    activate_command.add_argument("--draft", type=Path, required=True)
    activate_command.add_argument("--bootstrap-token-file", type=Path, required=True)
    activate_command.add_argument("--evidence", type=Path, required=True)
    prepare_command = commands.add_parser(
        "prepare", help="sign a portable activation request without the server secret"
    )
    prepare_command.add_argument("--key-file", type=Path, required=True)
    prepare_command.add_argument("--draft", type=Path, required=True)
    prepare_command.add_argument("--output", type=Path, required=True)
    submit_command = commands.add_parser(
        "submit", help="submit a signed request on the server without the KC key"
    )
    submit_command.add_argument("--api-url", required=True)
    submit_command.add_argument("--request", type=Path, required=True)
    submit_command.add_argument("--bootstrap-token-file", type=Path, required=True)
    submit_command.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()

    if args.command == "key-init":
        participant_key = create_encrypted_key(args.output, _passphrase(confirm=True))
        print(f"Encrypted KC participant key created. Public key: {participant_key}")
        return

    if args.command == "submit":
        prepared = PreparedActivation.model_validate_json(args.request.read_text(encoding="utf-8"))
        confirmation = input(f"Type SUBMIT {prepared.activation_body_digest[-12:]} to continue: ")
        response = submit_prepared_activation(
            api_url=args.api_url,
            prepared=prepared,
            bootstrap_token_file=args.bootstrap_token_file,
            evidence_path=args.evidence,
            confirmation=confirmation,
        )
        receipt = response.get("receipt", {})
        print(f"KC activation recorded. Receipt: {receipt.get('receipt_id', 'unavailable')}")
        return

    signer = load_encrypted_key(args.key_file, _passphrase())
    draft = _draft(args.draft)
    body = activation_body(draft, signer)
    digest = body_digest(body)
    print(json.dumps(body, indent=2, sort_keys=True))
    print(f"Activation body digest: {digest}")
    if args.command == "inspect":
        return
    confirmation = input(f"Type ACTIVATE {digest[-12:]} to continue: ")
    if args.command == "prepare":
        prepared = prepare_activation(draft=draft, signer=signer, confirmation=confirmation)
        _write_evidence(args.output, prepared.model_dump(mode="json"))
        print("Signed activation request created without a private key or server secret.")
        return
    response = activate(
        api_url=args.api_url,
        draft=draft,
        signer=signer,
        bootstrap_token_file=args.bootstrap_token_file,
        evidence_path=args.evidence,
        confirmation=confirmation,
    )
    receipt = response.get("receipt", {})
    print(f"KC activation recorded. Receipt: {receipt.get('receipt_id', 'unavailable')}")


if __name__ == "__main__":
    main()
