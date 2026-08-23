# KYN-000A Synthetic Trust Core

## Status and authority

KYN-000A is implemented for fictional-data-only design and verification. Five Letter
Agency is the KYN operator and operates it within The Party Party public project.
The Korey Streich Campaign Committee is the separate relying party and AI for
Wisconsin is its public program name. This slice does not activate an HTTP service,
accept real identity or relationship evidence, approve pilot policy, or authorize a
binding or determining poll.

## Executable workflow

`kyn.service.TrustCore` implements these deterministic transitions:

1. Register an exact claim-definition and policy version.
2. Enroll a pseudonymous `did:key` subject with no required PII.
3. Request that exact claim version.
4. Issue claim- and method-scoped verifier grants with caps and expiration.
5. Record direct invitations or non-transitive introductions.
6. Issue attestations only through matching, active grants and enforce self,
   duplicate-verifier, scope, expiry, and cap denials.
7. Issue a provisional credential from an initial attestation.
8. Promote it only when the synthetic corroboration, independence, and passed-audit
   rules all hold.
9. Select random or risk-based audits with deterministic selection receipts.
10. Record challenge, response, decision, appeal, and appeal-decision states.
11. Recalculate credentials after audit failure, challenge, appeal, grant revocation,
    or dependency expiration.
12. Emit public-safe events and receipts containing no subject, verifier, claim-
    request, attestation, or relationship identifiers.

The private in-memory dictionaries are deliberately not a persistence design. They
make the state transitions executable while real storage, migrations, encryption,
retention, backup, restore, and operator access controls remain gated.

## Machine boundaries

`schemas/trust-core-records.schema.json` defines subjects, claims, requests,
introductions, invitations, verifier grants, attestations, audits, challenges,
credentials, status, public events, and receipts. `kyn.contracts.to_record` produces
those exact shapes. The credential-presentation and ballot-authorization schemas
reject undeclared fields and use Ed25519 proofs. `api/openapi.v1.json` enumerates the
future Trust Core operations without making them live.

Presentations contain only issuer, audience-specific pairwise subject, exact claim
and policy version, assurance state and method class, issuance and expiration,
public status reference, receipt, and proof. They contain no KYN subject, participant
key, evidence, evidence handle, attestor, verifier grant, independence path, private
graph, contact, or account identity.

## Campaign and ballot separation

The campaign repository implements the other side of the boundary:

- Campaign Core registers an issuer through an explicit campaign approval record.
- It verifies the presentation signature, audience, expiry, approved status origin,
  and current status before retaining the strict minimum presentation.
- An immutable poll manifest fixes the accepted issuer, claim and policy versions,
  assurance state, method class, time window, and prospective revocation rule.
- A separately keyed authorization exchange emits a ballot ID, manifest hash,
  deterministic ballot-scoped nullifier, expiry, and signature only.
- The ballot service verifies that authorization, rejects reuse, and stores only an
  anonymous ballot digest and authorization fields.

KYN's presentation key cannot sign a campaign authorization. The ballot service has
neither the KYN presentation nor the campaign-side pairwise identifier. Revocation
blocks later authorization but, under the exact synthetic manifest rule, does not
silently rewrite a ballot already validly accepted.

## Authority exclusions

Verifier authority models and contracts have no popularity, patronage, donation,
activity, approval-volume, ideology, reward, or ballot-outcome inputs. There is no
universal score. Introductions do not confer verifier authority. Only an explicit
claim-specific grant based on the allowed synthetic procedure labels can authorize
an attestation.

## Verification

Run `make check`. The suite covers the full workflow, caps, independence, random and
risk audit records, challenge and appeal, dependency recalculation, pairwise audience
separation, proof verification, strict serialization, prohibited input rejection,
issuer approval, immutable manifest interpretation, key separation, ballot
unlinkability, one-time nullifiers, and prospective revocation behavior.
