# Know Your Neighbor (KYN)

KYN is an anonymous-first, claim-specific civic trust protocol operated by Five
Letter Agency as a component of The Party Party public project. The Party Party is
an FLA project/product name, not a separate legal entity. The Korey Streich Campaign
Committee is the separate campaign relying party and uses AI for Wisconsin as its
public-facing program name. Campaign Core may rely on scoped KYN credential
presentations under a documented agreement; the campaign does not operate KYN or
receive KYN evidence or private relationship graphs.

This repository contains the KYN Trust Core. KYN-000A established the deterministic
state machine and privacy boundaries. KYN-000B added the production-path public-beta
foundation: explicit verification bases, accountable authority tiers and grants,
participant-signed commands, a one-time KC bootstrap, durable PostgreSQL state,
idempotent command receipts, and an authenticated HTTP service. KYN-000C completes
the release, consent, peer-attestation, audit, challenge/appeal, recovery, privacy,
and portal paths. MEM-001 adds production-path ordinary-member snapshots and
determination-specific pairwise presentations while preserving KYN/campaign/ballot
separation. Source completion is not evidence that enrollment or a poll is live.

## Core promise

- Ordinary participants can use participant-controlled keys without providing the
  relying campaign a legal name, email, government ID, exact address, social login,
  or durable cross-context identifier.
- Friends, neighbors, and other approved claim-specific verifiers can attest that a
  qualification exists without giving the relying campaign the underlying PII.
- People who voluntarily accept more authority accept more accountability:
  individual authentication, scoped grants, caps, audits, conflicts controls,
  challenge, expiry, and potential public identification.
- Trust is not transitive and KYN never publishes a universal social-credit or
  reputation score.
- A ballot service receives only a ballot-scoped one-time authorization/nullifier,
  never a KYN subject or private graph.

## Repository map

- `docs/CONSTITUTION.md`: normative privacy, authority, and separation rules
- `docs/THREAT_MODEL.md`: initial attack and privacy analysis
- `docs/KYN-000C_IMPLEMENTATION.md`: source evidence and activation checklist
- `docs/DEPLOYMENT_AND_KC_ACTIVATION.md`: dark-deploy, secret-custody, backup, and
  explicit KC activation runbook
- `docs/POLICY_PARAMETERS.md`: unresolved pilot values and acceptance state
- `docs/OPERATOR_RELYING_PARTY_AGREEMENT.md`: exact Gate B organizational and data boundary
- `docs/MEM-001_ORDINARY_MEMBER_RELEASE.md`: exact ordinary-member release,
  limitations, campaign use, recovery, rollback, and acceptance
- `docs/KC_GATE_B_DESIGNATION.md`: exact one-subject bootstrap meaning and limits
- `docs/adr/`: accepted architecture decisions
- `schemas/`: public interoperability contracts
- `api/openapi.v1.json`: versioned Trust Core HTTP contract
- `migrations/`: durable PostgreSQL schema
- `src/kyn/`: state machine, participant proofs, persistence, and HTTP service
- `deploy/`: dark topology, activation client, separate encrypted backup, isolated restore, and host installers
- `tests/fixtures/`: synthetic examples only
- `tests/`: automated workflow, persistence, privacy, and authority tests
- `CONTRIBUTING.md`: public change process
- `SECURITY.md`: private vulnerability-reporting policy

## Status and licensing

KYN Gate B is deployed for exactly one KC-controlled `bootstrap_vouched` subject.
Runtime source `8058ce7ac0d36f3a8dda140d735cbb28276a410d` runs a loopback-only
healthy API and unpublished PostgreSQL database. Release `1.0.0`, exact-version
consent, and one active replacement recovery commitment are active. The bootstrap
endpoint is retired. Ordinary enrollment, claims, credentials, polls, and sensitive
evidence remain closed.

KYN is licensed under the Apache License 2.0. Five Letter Agency operates KYN within
The Party Party public project. The Korey Streich Campaign Committee is the separate
AI for Wisconsin relying party. The exact 1.0.0 terms, privacy notice, consent
notice, security process/contact, provisional-storage disclosure, and this
operator/relying-party boundary are accepted operationally for the bounded KC-first
Gate B package; that acceptance is not independent legal advice.

Gate B uses the disclosed unencrypted provisional volume under the accepted
one-subject exception. Separate KYN/FLA Restic credentials and Pi repository,
pre-activation credential rotation, encrypted backup, and isolated no-network
restore passed before activation; post-activation and post-human-acceptance backups
and restores also pass. Public-safe evidence is under `docs/evidence/`.

The bounded one-subject Gate B release is `production-accepted`. A real KC recovery
request rotated the participant key, retired the prior key, consumed the original
commitment, and established a new secret-service-backed commitment. A real export
privacy request was approved, remained subject-scoped, and persisted no export.
Post-acceptance encrypted backup and isolated restore passed.

MEM-001 release `2.0.0` is accepted for implementation but is not active. Its source
opens pseudonymous self-service campaign membership without per-member approval and
adds signed eligible-count snapshots plus short-lived determination-specific
presentations. One poll authorization means one KYN subject, not proven
one-natural-person uniqueness. No sensitive evidence, verified-Wisconsin claim,
representative result, statutory meaning, or member-submitted question is
authorized.

No fake participant records may be seeded into a live environment. Later
participants must enter through real, consented journeys after exact release
activation. Deterministic keys and secrets in tests are public test material and
must never be reused.

## Verify

Run `make check` on Python 3.13. It verifies the lock, package build, formatting,
lint, strict typing, JSON Schemas and OpenAPI structure, deterministic workflows,
durable restart/idempotency behavior, signed participant actions, and adversarial
privacy and authority boundaries.
