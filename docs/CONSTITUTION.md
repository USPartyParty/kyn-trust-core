# KYN Constitution

## Status

This is the normative source contract for KYN. `MUST`, `MUST NOT`, `SHOULD`, and
`MAY` are requirements. It authorizes production-path implementation and automated
testing. It does not, by itself, open enrollment, approve participant notices,
activate a poll, or establish that a credential proves a statutory qualification.

## Operator and relying party

Five Letter Agency is the KYN operator and operates KYN as a component of The Party
Party public project. The Party Party is an FLA project/product name, not a separate
legal entity. The Korey Streich Campaign Committee is the separate relying party and
uses AI for Wisconsin as its public-facing campaign program name. Shared ownership
or collaboration is disclosed but does not combine legal identity, authority,
funds, contracts, databases, evidence, keys, credentials, logs, backups, or public
claims.

Campaign use or paid operation MUST use the applicable written service/data
agreement, public notices, and campaign-finance, privacy, security, and legal or
compliance review. The operator cannot exercise campaign authority merely by
operating KYN; the campaign cannot inspect KYN evidence or private graph state.

## Privacy asymmetry

Institutions, rules, operators, verifiers, audits, decisions, and aggregate outcomes
SHOULD be maximally inspectable. An ordinary participant MAY remain anonymous or
pseudonymous. Enrollment MUST NOT require a legal name, email, exact address,
government identifier, social login, or stable cross-context identifier.

Optional contact and recovery channels require separate, purpose-specific consent.
Evidence is collected only for an approved claim method, stored in a separately
encrypted short-retention vault, and never included in a relying-party presentation.

## Claim-specific trust

KYN proves versioned claims, not people. An attestation applies only to the stated
claim, subject, method, time, and policy version. Trust is not automatically
transitive. Corroboration, independence, caps, expiry, audits, challenges, appeals,
and revocation are explicit policy inputs.

An attestation MAY create a provisional credential. Active status requires the
published corroboration and risk rules. Invalidating an attestation, verifier grant,
audit result, or upstream credential MUST deterministically recalculate dependent
credentials without disclosing private graph edges.

Every attestation and credential MUST identify its exact verification basis. A
self-assertion, KC bootstrap voucher, peer attestation, official-source check,
independent review, and audit corroboration are distinct and MUST NOT be presented
as interchangeable. A relying party MUST state the bases it accepts in an immutable
manifest.

## Accountable authority

Verifier, adjudicator, key-custodian, and operator authority is voluntary,
claim-specific, least-privileged, capped, expiring, audited, challengeable, and
revocable. Higher authority MAY require real-world proofing and public identification.
Promotion depends on correct audited procedure and correction behavior, never
popularity, wealth, ideology, approval volume, patronage, donations, engagement, or
ballot outcomes. KYN MUST NOT compute or expose a universal social score.

The initial root is a single, explicit, non-transitive designation of KC Streich.
It exists to begin the real system without fabricated users or implied third-party
review. Bootstrap authority MUST be participant-key controlled, publicly labeled,
expiring, and unable to disguise a bootstrap-vouched claim as peer or official
verification. Later authority MUST be an explicit scoped grant or an audited
promotion. No fake participant record may be inserted into a live environment.

## Relying-party and ballot separation

A relying party receives only issuer, claim and policy version, pairwise subject,
assurance/method class, issuance/expiry, status reference, and presentation receipt.
It receives no KYN subject, account identity, evidence handle, attestor identity, or
private graph.

A separate authorization exchange evaluates the presentation against an immutable
poll manifest and emits a ballot-scoped one-time token/nullifier. The ballot service
MUST NOT receive a KYN subject, relying-party principal, email, external account, or
verifier relationship. Rewards and engagement MUST NOT change eligibility or ballot
weight.

## Public change governance

Anyone may propose a change. A proposal does not change a live rule until the
operator accepts an exact version, publishes rationale and compatibility impact,
passes applicable gates, and supplies a migration plan. Safety vulnerabilities and
private participant evidence use the nonpublic security process.
