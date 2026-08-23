# Initial Threat Model

## Protected outcomes

- ordinary participants are not identified by a relying party or public artifact
- a verifier cannot create unlimited or unreviewed credentials
- a compromised service cannot traverse the KYN-to-ballot identity boundary
- corrections, challenges, audits, expiry, and revocation propagate predictably
- organizational collaboration does not become silent data, authority, or fund merge

## Principal threats and required controls

| Threat | Initial controls |
| --- | --- |
| Sybil or collusive attestation ring | independent corroboration, per-claim caps, reciprocal/circular-path detection, random and risk-based audits, seeded synthetic abuse tests |
| Powerful verifier rubber-stamps claims | promotion by audited procedure, not approval volume; expiry, cap reduction, suspension, dependency recalculation |
| Campaign correlates KYN and ballot identities | pairwise presentations, separate authorization exchange, ballot-scoped nullifiers, separate stores/keys/logs, correlation tests |
| Evidence breach | exceptional collection only, encrypted Evidence Vault, opaque handles, least privilege, short retention, no body logging |
| Relationship-graph exposure | graph never public or campaign-readable; aggregate publication with small-cell suppression and differential disclosure review |
| Recovery becomes identity backdoor | isolated recovery mapping, strong ceremony, old-binding revocation, duplicate review, audit receipt |
| Rewards distort verification | reward completed audited procedure only; no reward for approvals, volume, position, purchase, contribution, or outcome |
| Shared ownership collapses organizations | written agreement, separate accounts/stores/keys/backups/notices, fair-value and campaign-finance review, auditable interfaces |
| Policy change silently weakens privacy | exact versions, public decision record, compatibility analysis, migration plan, independent review before higher-consequence use |
| Bootstrap authority is mistaken for independent verification | explicit `bootstrap_vouched` basis, one named non-transitive bootstrap, immutable claim/policy versions, relying-party manifest requirements |
| Stolen participant key or replayed command | Ed25519 body-bound action proof, short clock window, nonce-derived idempotency key, exact replay response, revoke/replace path |
| Delegated authority expands itself | capability/scope/tier subset rules, maximum delegation depth, expiry, usage caps, cascade revocation |
| Failed deployment creates false public confidence | source/deployed status separation, fail-closed production configuration, explicit release record and public notice |

## Current release exclusions

The source contains a real-participant-capable beta foundation but no live deployment
is established by this repository. It does not authorize SSNs, government-ID images,
biometrics, full birth dates, a general evidence vault, a consequential statutory
credential, campaign payment, or a binding/determining ballot. Test fixtures remain
fictional and must never be promoted into live state.
