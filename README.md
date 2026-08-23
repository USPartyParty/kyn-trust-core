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
and portal paths in source. Source completion is not evidence that a live service or
poll has been opened.

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
- `docs/adr/`: accepted architecture decisions
- `schemas/`: public interoperability contracts
- `api/openapi.v1.json`: versioned Trust Core HTTP contract
- `migrations/`: durable PostgreSQL schema
- `src/kyn/`: state machine, participant proofs, persistence, and HTTP service
- `tests/fixtures/`: synthetic examples only
- `tests/`: automated workflow, persistence, privacy, and authority tests
- `CONTRIBUTING.md`: public change process
- `SECURITY.md`: private vulnerability-reporting policy

## Status and licensing

KYN-000C and its deployment/activation tooling are implemented in source. A dark,
empty Optiplex deployment runs a loopback-only healthy API and unpublished
PostgreSQL database; no operator release, subject, command, claim, credential, or
poll is active.

KYN is licensed under the Apache License 2.0. Five Letter Agency operates KYN within
The Party Party public project. The Korey Streich Campaign Committee is the separate
AI for Wisconsin relying party. The exact 1.0.0 terms, privacy notice, consent
notice, security process/contact, provisional-storage disclosure, and this
operator/relying-party boundary are accepted operationally for the bounded KC-first
Gate B package; that acceptance is not independent legal advice.

Gate B permits exactly one KC-controlled `bootstrap_vouched` subject on the disclosed
unencrypted provisional volume as an explicit exception to the earlier
encrypted-replacement-storage gate. The exception requires a separate encrypted KYN
backup repository, independent credentials, successful isolated restore, rotated
pre-activation service secrets, operator recovery, exact designation and backup
evidence hashes, and KC's locally generated encrypted participant key before
activation. It authorizes no sensitive evidence, ordinary public enrollment,
verified-Wisconsin claim, binding or determining poll, or durable-production claim.
Backup failure, inability to restore, unexpected exposure, or loss of separation
stops the beta.

No fake participant records may be seeded into a live environment. KC is the only
permitted first bootstrap subject. Later participants must enter through real,
consented journeys after a separate Gate C opening decision. Deterministic keys and
secrets in tests are public test material and must never be reused.

## Verify

Run `make check` on Python 3.13. It verifies the lock, package build, formatting,
lint, strict typing, JSON Schemas and OpenAPI structure, deterministic workflows,
durable restart/idempotency behavior, signed participant actions, and adversarial
privacy and authority boundaries.
