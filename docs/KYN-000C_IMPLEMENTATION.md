# KYN-000C implementation record

Status: implemented and verified in source on 2026-07-30; not deployed and no real
participant, KC bootstrap, claim, verifier grant, or poll has been activated.

## Implemented boundary

KYN-000C completes the authenticated public-beta service path built on KYN-000B:

- an operator-release record binds the exact release, participant notice, terms,
  privacy notice, public operator contact, disclosed storage posture, and backup
  evidence reference;
- release activation refuses sensitive-evidence collection and enrollment fails
  closed until a release is active;
- ordinary participants create Ed25519 keys without supplying a name, email, social
  login, exact address, government ID, or identity evidence;
- participant commands use timestamped, nonce-bearing signatures over an exact
  operation and canonical request-body digest;
- consent binds exact notice versions and named KYN purposes;
- recovery stores a one-way commitment, requires proof from the replacement key,
  requires an accountable operator decision, and rotates only the pseudonymous key
  binding;
- export, correction/invalidation, consent withdrawal, and deletion requests are
  executable. Deletion removes the participant-key binding, withdraws consent,
  revokes subject authority, and invalidates dependent attestations and credentials;
- peer invitations, accountable introductions, scoped attestations, random/risk
  audits, challenges, responses, decisions, and appeals are exposed through the
  authenticated HTTP API;
- live peer attestations cannot submit a self-invented independence label. They must
  reference an unexpired introduction matching the exact claim and verifier. KYN
  derives a non-reversible path token from the claim and introducer, so repeated
  introductions from one source cannot manufacture independent paths;
- public endpoints expose only the active release, credential status, public-safe
  events, and privacy-safe receipts.

The Party Party portal implements browser-held, non-exportable participant keys,
release/notice display, enrollment, consent, recovery setup/request, claim request,
neighbor invitation, verifier attestation, challenge/follow-up, privacy request, and
approved-export download. Its backend-for-frontend relays bounded JSON, blocks the
bootstrap endpoint, forwards no bearer credential or cookie, and never receives the
participant private key. A recovery code passes transiently over TLS only for a
recovery request and is not retained. The service exposes no evidence-vault or
private-graph retrieval endpoint through this relay.

## KC bootstrap alignment

KC Streich remains the one and only first bootstrap designation. The command creates
a pseudonymous subject, an expiring and publicly labeled operator grant, and the
first operator-release record atomically. It requires KC's participant-key proof and
the one-time out-of-band bootstrap secret. No legal name, address, SSN, ID image, or
other PII is a protocol input. KC's initial claim must still use the explicit
`bootstrap_vouched` basis and can never be presented as independent, official,
statutory, or elector verification.

The bootstrap is source-complete but MUST NOT be exercised until the checklist below
is accepted. Tests use public fictional fixtures only; they do not seed a live
service.

## Privacy semantics

KYN deletion is cryptographic unlinking plus prospective trust invalidation, not
silent rewriting of public receipts. Pseudonymous audit/tombstone records needed to
explain prior decisions remain under the disclosed retention policy. No command row
stores a recovery code: durable idempotency retains only the request digest. Portable
exports are limited to records involving the requesting subject and do not include
unrelated participant keys or graph edges.

## Verification evidence

The source gate currently passes:

- lockfile verification and package build;
- formatting, Ruff lint, and strict mypy;
- JSON Schema and curated OpenAPI reference checks;
- 39 state-machine, authority, persistence, API, privacy, recovery,
  deployment-secret, activation-custody, and adversarial tests;
- durable restart and KYN-000B snapshot-shape migration;
- a full signed KYN-000C HTTP lifecycle, including rejection of an invented
  independence path.

The portal separately passes ESLint, strict TypeScript, and an optimized Next.js
production build with the `/kyn` page, bounded `/api/kyn/[...path]` relay, and
hash-verified release `1.0.0` candidate routes for exact terms, privacy, consent,
security, and provisional-storage disclosures.

The deployment bundle now includes pinned containers, create-once file-backed
service secrets, a digest-pinned migration runner, a loopback-only API topology, and
a two-stage activation client. KC's encrypted participant key remains on KC's
workstation; only a signed, secret-free request crosses to the Optiplex, where the
one-time bootstrap token remains. Response validation refuses a changed participant
key, public label, release field, or missing receipt before evidence is written.

## Activation checklist

Before the real KC command or public participant enrollment:

1. Select the open-source license and add `LICENSE`.
2. Accept and publish exact versioned participant terms and privacy notice at the
   URLs placed in the release command.
3. Accept a public security-reporting address and response targets.
4. Create fresh production signing, pairwise, receipt, and one-time bootstrap secret
   files with restrictive permissions; never reuse test material.
5. Apply the PostgreSQL migration, restrict service/network access, verify TLS, and
   confirm request bodies are absent from proxy and application logs.
6. Complete and hash an encrypted backup/restore exercise. If the provisional disk
   is used, publish its availability/data-loss risk and record its
   `provisional_beta` storage posture.
7. Review the exact KC designation reference, expiry, release/notice versions,
   operator contact, URLs, and backup evidence reference before signing.
8. Execute the one-time KC bootstrap from a trusted client, archive the receipt, and
   verify the public release endpoint before enabling portal enrollment.
9. Run the portal enrollment/recovery/privacy browser journeys against the deployed
   topology and publish redacted results.
10. Register only accepted claim definitions. Do not enable sensitive evidence,
    binding/determining polls, or statutory claims.

Independent legal, privacy, security, and accessibility review remains required for
higher-consequence expansion. KYN-000C source completion does not waive those gates.
