# Policy Parameter Register

Architecture values marked `accepted` may be implemented in production-path source.
Pilot values marked `pending` require an exact operator decision and the applicable
review before they become live policy.

| Parameter | State | Current direction |
| --- | --- | --- |
| KYN operator | accepted | Five Letter Agency, operating KYN within The Party Party public project |
| Project status | accepted | The Party Party is an FLA public project/product name, not a separate legal entity |
| Campaign relationship | accepted | The Korey Streich Campaign Committee is the separate relying party; AI for Wisconsin is its public program name |
| Ordinary participant identity | accepted | anonymous/pseudonymous participant-controlled key |
| Authority model | accepted | voluntary, claim-specific, capped, expiring, audited |
| Initial authority | accepted | one public, non-transitive KC Streich bootstrap controlled by KC's participant key |
| Assurance labeling | accepted | exact verification basis travels with attestations, credentials, presentations, and poll manifests |
| Live seed data | prohibited | no fictional participants or attestations in a live environment; deterministic fixtures remain test-only |
| Universal social score | prohibited | no numeric or global reputation score |
| Ballot identity | accepted | ballot-scoped one-time authorization/nullifier |
| Phase 2 claim vocabulary | pending | community-corroborated Wisconsin connection; unique pilot participant |
| Corroboration and independence | pending | two independent paths by default; household and circularity rules require acceptance |
| Audit sample and escalation rates | pending | publish before pilot; combine random and risk-based selection |
| Evidence classes and retention | pending | minimize; exceptional encrypted vault only |
| Verifier caps and promotion thresholds | pending | no verifier dominates a pilot; promotion follows audited procedure |
| Small-cell threshold | pending | suppress or combine risky aggregate cells |
| Recovery and successor custodians | accepted for Gate B | KC/FLA is the initial recovery custodian; KYN uses a separately encrypted Pi repository and independent credentials, never the Campaign Committee backup repository; isolated restore must pass before activation |
| Gate B storage posture | accepted exception | one KC-controlled subject may activate on the disclosed unencrypted provisional volume only after separate encrypted backup/restore; no sensitive evidence or ordinary enrollment; loss/backup failure stops the beta |
| Open-source license | accepted | Apache License 2.0 |

## Automated-test profile

`kyn-000a-synthetic-v1` is an executable test profile, not an accepted pilot policy.
It uses two attestations, two distinct independence-path labels, one passed audit, a
30-day credential lifetime, and a ten-minute presentation lifetime so every state
transition and boundary can be tested deterministically. These numbers do not settle
the pending pilot values above and MUST NOT be used with real participants.

## KYN-000C public-beta source profile

`kyn-000c-public-beta-v1` is the production-path source profile. It enables explicit
authority enforcement, release-gated enrollment, exact consent, signed participant
commands, the single KC bootstrap, accountable peer paths, and durable state. It
does not silently accept the pending claim, concentration, retention, or poll
parameters above. A deployed instance must register exact claim definitions and
accepted assurance bases through an authorized, receipted command.
