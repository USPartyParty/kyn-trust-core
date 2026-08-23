from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from kyn import ClaimDefinition, to_record
from kyn.models import (
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
    ChallengeState,
    ClaimRequest,
    ConsentRecord,
    Credential,
    CredentialState,
    CredentialStatus,
    Introduction,
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
    VerifierGrant,
)

ROOT = Path(__file__).parents[1]


def load(relative: str) -> dict[str, object]:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def validate(schema_name: str, fixture_name: str) -> None:
    validator = Draft202012Validator(load(f"schemas/{schema_name}"), format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(load(f"tests/fixtures/{fixture_name}")), key=str)
    assert not errors, [error.message for error in errors]


def test_minimum_disclosure_presentation_contract() -> None:
    validate("credential-presentation.schema.json", "valid-credential-presentation.json")


def test_ballot_authorization_contract() -> None:
    validate("ballot-authorization.schema.json", "valid-ballot-authorization.json")


def test_ballot_contract_forbids_identity_linkage_fields() -> None:
    schema = load("schemas/ballot-authorization.schema.json")
    fixture = load("tests/fixtures/valid-ballot-authorization.json")
    forbidden = {
        "kyn_subject",
        "pairwise_subject",
        "campaign_principal",
        "email",
        "external_account",
        "attestor",
        "verifier",
    }
    assert forbidden.isdisjoint(fixture)
    assert schema["additionalProperties"] is False


def test_all_json_schemas_are_well_formed_and_identifiers_are_unique() -> None:
    identifiers: set[str] = set()
    for path in sorted((ROOT / "schemas").glob("*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        assert schema["$id"] not in identifiers
        identifiers.add(schema["$id"])


def test_openapi_exposes_every_kyn_000a_transition() -> None:
    contract = load("api/openapi.v1.json")
    operations = {
        operation["operationId"]
        for path in contract["paths"].values()
        for operation in path.values()
    }
    assert {
        "registerClaimDefinition",
        "createSubject",
        "requestClaim",
        "grantVerifier",
        "inviteAttestor",
        "introduceAttestor",
        "issueAttestation",
        "selectAudit",
        "decideAudit",
        "openChallenge",
        "respondToChallenge",
        "decideChallenge",
        "appealChallenge",
        "decideAppeal",
        "revokeVerifierGrant",
        "presentCredential",
        "getCredentialStatus",
        "listPublicEvents",
        "getReceipt",
        "activateBootstrapAuthority",
        "grantAuthority",
        "promoteAuthority",
        "revokeAuthority",
        "issueBootstrapAttestation",
        "acceptConsent",
        "registerRecoveryCommitment",
        "requestRecovery",
        "decideRecovery",
        "requestPrivacyAction",
        "processPrivacyAction",
        "exportPrivacyData",
        "getOperatorRelease",
        "registerOperatorRelease",
    } <= operations

    assert "bootstrapBearer" in contract["components"]["securitySchemes"]
    assert "participantActionProof" in contract["components"]["securitySchemes"]

    for path in contract["paths"].values():
        for method, operation in path.items():
            assert "responses" in operation
            if method == "post":
                assert "requestBody" in operation

    def references(value: object):
        if isinstance(value, dict):
            if isinstance(reference := value.get("$ref"), str):
                yield reference
            for nested in value.values():
                yield from references(nested)
        elif isinstance(value, list):
            for nested in value:
                yield from references(nested)

    for reference in references(contract):
        if not reference.startswith("#/"):
            continue
        resolved: object = contract
        for component in reference.removeprefix("#/").split("/"):
            assert isinstance(resolved, dict)
            assert component in resolved
            resolved = resolved[component]


def test_public_contracts_forbid_pii_influence_and_private_graph_fields() -> None:
    trust_schema = load("schemas/trust-core-records.schema.json")
    serialized = json.dumps(trust_schema)
    prohibited_authority_inputs = {
        "popularity",
        "patronage",
        "donations",
        "activity",
        "approval_volume",
        "ballot_outcome",
    }
    assert all(term not in serialized for term in prohibited_authority_inputs)

    presentation = load("schemas/credential-presentation.schema.json")
    presentation_fields = set(presentation["properties"])
    private_fields = {
        "kyn_subject",
        "subject_id",
        "participant_key",
        "attestor",
        "verifier",
        "evidence",
        "graph",
    }
    assert private_fields.isdisjoint(presentation_fields)
    assert presentation["additionalProperties"] is False


def test_executable_records_serialize_to_the_machine_contract() -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)
    definition = ClaimDefinition(
        claim_type="community_corroborated_wisconsin_connection",
        definition_version="0.1.0",
        policy_version="0.1.0",
        method_class="two_independent_social_paths",
    )
    records = [
        definition,
        Subject(
            subject_id="sub_00000001",
            participant_key="did:key:zSyntheticParticipant00000001",
            created_at=now,
        ),
        OperatorRelease(
            release_id="rel_00000001",
            release_version="1.0.0",
            notice_version="1.0.0",
            terms_url="https://usparty.party/kyn/terms/1.0.0",
            privacy_url="https://usparty.party/kyn/privacy/1.0.0",
            operator_contact="privacy@usparty.party",
            storage_posture=StoragePosture.PROVISIONAL_BETA,
            backup_evidence_reference="sha256:" + "b" * 64,
            sensitive_evidence_enabled=False,
            activated_by_authority_grant_id="agr_00000001",
            activated_at=now,
        ),
        ConsentRecord(
            consent_id="cns_00000001",
            subject_id="sub_00000001",
            notice_version="1.0.0",
            purposes=frozenset({"kyn_claim_processing", "kyn_recovery"}),
            granted_at=now,
        ),
        RecoveryCommitment(
            recovery_commitment_id="rcm_00000001",
            subject_id="sub_00000001",
            commitment="sha256:" + "c" * 64,
            created_at=now,
        ),
        RecoveryCase(
            recovery_case_id="rcv_00000001",
            subject_id="sub_00000001",
            recovery_commitment_id="rcm_00000001",
            prior_key_digest="sha256:" + "d" * 64,
            replacement_participant_key="did:key:ed25519:" + "e" * 43,
            requested_at=now,
            state=RecoveryState.PENDING,
        ),
        PrivacyRequest(
            privacy_request_id="prv_00000001",
            subject_id="sub_00000001",
            kind=PrivacyRequestKind.EXPORT,
            reason_code="participant_requested",
            requested_at=now,
            state=PrivacyRequestState.PENDING,
        ),
        ClaimRequest(
            request_id="clm_00000001",
            subject_id="sub_00000001",
            definition=definition,
            requested_at=now,
        ),
        VerifierGrant(
            grant_id="grt_00000001",
            verifier_subject_id="sub_00000002",
            claim_type=definition.claim_type,
            method_classes=frozenset({definition.method_class}),
            attestation_cap=2,
            issued_at=now,
            expires_at=now + timedelta(days=60),
            authority_basis="audited_procedure",
        ),
        BootstrapAuthority(
            bootstrap_id="bst_00000001",
            policy_version="1.0.0",
            authority_subject_id="sub_00000001",
            public_label="KC Streich",
            designation_reference="sha256:" + "a" * 64,
            activated_at=now,
            expires_at=now + timedelta(days=365),
        ),
        AuthorityGrant(
            authority_grant_id="agr_00000001",
            holder_subject_id="sub_00000001",
            issuer_authority_grant_id=None,
            capabilities=frozenset(AuthorityCapability),
            claim_types=frozenset({"*"}),
            method_classes=frozenset({"*"}),
            tier=AuthorityTier.OPERATOR,
            basis=AuthorityBasis.BOOTSTRAP_DESIGNATION,
            issued_at=now,
            expires_at=now + timedelta(days=365),
            usage_cap=None,
            used_count=0,
            can_delegate=True,
            delegation_depth=0,
            max_delegation_depth=4,
            public_accountability_label="KC Streich",
        ),
        AuthorityPromotion(
            promotion_id="prm_00000001",
            subject_id="sub_00000002",
            source_authority_grant_ids=("agr_00000002",),
            resulting_authority_grant_id="agr_00000003",
            prior_tier=AuthorityTier.PROVISIONAL_VERIFIER,
            resulting_tier=AuthorityTier.VERIFIER,
            passed_audit_ids=("aud_00000001",),
            decided_by_authority_grant_id="agr_00000001",
            decided_at=now,
        ),
        AttestorInvitation(
            invitation_id="inv_00000001",
            request_id="clm_00000001",
            verifier_subject_id="sub_00000002",
            created_at=now,
            expires_at=now + timedelta(days=7),
        ),
        Introduction(
            introduction_id="int_00000001",
            request_id="clm_00000001",
            introducer_subject_id="sub_00000002",
            invited_verifier_subject_id="sub_00000003",
            created_at=now,
            expires_at=now + timedelta(days=7),
        ),
        Attestation(
            attestation_id="att_00000001",
            request_id="clm_00000001",
            grant_id="grt_00000001",
            verifier_subject_id="sub_00000002",
            independence_path="path_neighborhood_a",
            method_class=definition.method_class,
            issued_at=now,
            expires_at=now + timedelta(days=30),
            state=AttestationState.ACTIVE,
        ),
        Audit(
            audit_id="aud_00000001",
            attestation_id="att_00000001",
            basis=AuditBasis.RANDOM,
            selection_receipt="sel_SyntheticSelectionReceipt000000000001",
            selected_at=now,
            state=AuditState.PENDING,
        ),
        Challenge(
            challenge_id="chg_00000001",
            attestation_id="att_00000001",
            reason_code="synthetic_report",
            opened_at=now,
            state=ChallengeState.OPEN,
        ),
        Credential(
            credential_id="crd_00000001",
            request_id="clm_00000001",
            definition=definition,
            state=CredentialState.PROVISIONAL,
            dependency_attestation_ids=("att_00000001",),
            issued_at=now,
            expires_at=now + timedelta(days=30),
            status_reference="https://kyn.usparty.party/status/crd_00000001",
            updated_at=now,
        ),
        CredentialStatus(
            status_reference="https://kyn.usparty.party/status/crd_00000001",
            state=CredentialState.PROVISIONAL,
            updated_at=now,
        ),
        PublicEvent(
            event_id="evt_00000001",
            event_type="credential.presented",
            aggregate_type="presentation",
            occurred_at=now,
            policy_profile="kyn-000a-synthetic-v1",
            public_attributes={"outcome": "issued"},
        ),
        Receipt(
            receipt_id="rcp_SyntheticOperationReceipt0000000000001",
            operation="credential.presented",
            outcome="issued",
            occurred_at=now,
            event_id="evt_00000001",
            policy_profile="kyn-000a-synthetic-v1",
        ),
    ]
    validator = Draft202012Validator(
        load("schemas/trust-core-records.schema.json"),
        format_checker=FormatChecker(),
    )
    for record in records:
        errors = sorted(validator.iter_errors(to_record(record)), key=str)
        assert not errors, [error.message for error in errors]
