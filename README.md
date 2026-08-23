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

KYN-000C and its deployment/activation tooling are implemented in source. The
Optiplex is the active deployment target. Deployment advances concurrently with
replacement storage and monitored power as the first public financial and polling
goal. The architecture,
operator designation, KC-first bootstrap, and requirement to label every assurance
basis are accepted directions. Activation still requires fresh secret material,
the PostgreSQL migration, restricted network exposure, backup/restore evidence,
KC acceptance of the staged participant notices and operating terms, and an accepted
operator release command. No fake participant records may be seeded into a live environment. KC is the
only permitted first bootstrap subject; later participants must enter through real,
consented journeys.

The current dark, empty deployment may use the dedicated automatically mounted
integration volume with only rotatable pre-activation service credentials. It must
not activate KC, admit a participant, issue an authoritative credential, or retain
irreplaceable evidence. Before any of those transitions, state moves to encrypted
replacement storage, the pre-activation credentials rotate, and operator recovery
plus clean restore must pass.

The deterministic keys and secrets in tests are public test material and must never
be reused. The current beta path stores pseudonymous protocol state and does not
require names, emails, SSNs, government-ID images, or exact addresses. Exceptional
evidence collection remains unimplemented and is not authorized. A public beta does
not make a credential statutory proof of residence, citizenship, elector status, or
identity, and no binding or determining poll is authorized.

The exact KYN 1.0.0 terms, privacy notice, consent notice, provisional-storage
disclosure, and proposed security process are now staged as hash-verified public
release candidates in the Party Party portal. KC activation acceptance, any required
inter-organization agreement, backup/restore evidence, and the open-source license
remain release gates. Until a license is selected and a
`LICENSE` file is added, this repository alone grants no permission to copy, modify,
or distribute the code.

## Verify

Run `make check` on Python 3.13. It verifies the lock, package build, formatting,
lint, strict typing, JSON Schemas and OpenAPI structure, deterministic workflows,
durable restart/idempotency behavior, signed participant actions, and adversarial
privacy and authority boundaries.
