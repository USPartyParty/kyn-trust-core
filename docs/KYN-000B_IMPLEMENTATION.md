# KYN-000B Public-Beta Foundation

## Status

KYN-000B is implemented and verified in source. It converts the KYN-000A
deterministic model into a durable, authenticated service foundation without
creating a fake live population. It does not claim that a service is deployed,
that participant terms have been accepted, or that any poll is open.

Five Letter Agency operates KYN within The Party Party public project. The Korey
Streich Campaign Committee is a separate relying party using the AI for Wisconsin
public name. Their keys, authority, private records, and service decisions remain
separate.

## Verification-basis contract

KYN records the reason a claim has assurance rather than flattening every outcome
into “verified.” The machine-readable bases are:

- `self_asserted`
- `bootstrap_vouched`
- `peer_attested`
- `official_source_checked`
- `independently_reviewed`
- `audit_corroborated`

Claim definitions state the allowed and required bases and their corroboration,
independence, and audit thresholds. Attestations, credentials, and minimum-
disclosure presentations carry the resulting bases. Campaign Core poll manifests
state the bases they accept. A KC bootstrap claim therefore cannot be mistaken for
peer corroboration or an official-source check.

## Accountable authority

Authority is an explicit record, not a reputation score. Grants contain a holder,
issuer, capability set, claim and method scopes, tier, basis, expiry, optional usage
cap, delegation limit, and revocation state. The tiers are participant, provisional
verifier, verifier, steward, and operator. Delegation may only narrow capabilities,
scope, tier, expiry, and depth. Promotion advances one tier after passed audits of
the subject's actual verification procedure. Revoking an upstream grant revokes its
delegated descendants and recalculates dependent credentials.

Popularity, patronage, donations, activity, approval volume, ideology, rewards, and
ballot outcomes are absent from the authority contract and transition inputs.

## KC-first bootstrap

The beta begins with one explicit root designation:

1. KC creates a participant-controlled Ed25519 key.
2. KC signs the complete bootstrap request body.
3. The service also requires the out-of-band one-time bootstrap token.
4. The accepted policy requires the exact public label `KC Streich` and a SHA-256
   designation reference.
5. The service creates one pseudonymous subject and one expiring operator grant.
6. Durable state prevents a second root bootstrap.

The bootstrap is public, non-transitive, and labeled as `bootstrap_vouched`. It is a
documented starting basis, not independent review. Later participants are real,
consenting people and enter through normal signed journeys; live seed data is
prohibited.

## Durable authenticated service

The FastAPI service accepts participant-key-controlled commands. Each mutation signs
the operation name, nonce, timestamp, and canonical request-body digest. The nonce
and actor key derive an idempotent command identifier. An exact retry returns the
stored result; reuse with different input fails closed.

The PostgreSQL migration creates one transactional private-state snapshot and an
append-only command/receipt table. Each command locks the state row, restores the
deterministic core, performs one transition, and commits the new snapshot and receipt
together. Production configuration requires HTTPS, PostgreSQL, and restrictive
secret-file permissions. Migrations are an explicit prestart operation; the service
does not mutate its schema at startup.

The current endpoints cover subject creation, one-time bootstrap activation, claim
definition and request creation, bootstrap-vouched issuance, authority grant,
audited promotion, cascade revocation, participant-controlled presentation, public
credential status, public-safe events, and receipts. KYN-000A's remaining peer,
audit, challenge, and appeal transitions remain executable in the deterministic core
and machine contracts; completing their authenticated HTTP journeys is the next
service slice.

## Campaign relying-party boundary

Campaign Core retains only the pairwise presentation already permitted by KYN-000A,
now including the exact verification bases. An immutable poll manifest can require
specific bases. A presentation that is cryptographically valid but lacks a required
basis is rejected before ballot authorization. Campaign Core still cannot request a
KYN subject, evidence, attestor, verifier grant, or graph edge, and the ballot
service still receives only its ballot-scoped authorization/nullifier.

## Activation boundary

Before a live KC bootstrap, the operator must record fresh production keys and
secrets, apply the migration to the intended PostgreSQL instance, restrict network
access, verify backup and restore, publish the applicable notice/terms and operator
contact, and create an exact release record. Campaign use additionally needs the
applicable campaign/operator agreement and review. These are deployment and
governance gates, not reasons to fabricate a preproduction population.
