# MEM-001 Ordinary Campaign-Member Release

- Release and notice version: `2.0.0`
- State: accepted implementation input; not effective until the accountable KYN operator signs and the service accepts the exact release
- Operator: Five Letter Agency within The Party Party public project
- Relying party: Korey Streich Campaign Committee through AI for Wisconsin
- Decision date: 2026-08-24

## Exact scope

Release 2.0.0 prospectively opens ordinary pseudonymous campaign membership. A person creates and controls an Ed25519 key, accepts the exact notice, and may configure recovery without a legal name, email, social login, exact address, government identifier, sensitive evidence, or per-member operator approval.

An eligible member is one active KYN subject with current `kyn_campaign_member_ballot` consent. This release enforces one authorization per KYN subject and poll. It does not prove that one natural person cannot enroll multiple KYN subjects. Every campaign result must disclose that limitation and must not be called representative of Wisconsin, verified residency, voter registration, elector eligibility, an official election, or a statutory credential.

KYN may return a signed eligible-member count and snapshot digest without a subject list. After a participant-key proof, KYN may issue a short-lived determination-specific pairwise member presentation. The presentation contains no KYN subject, participant key, recovery information, attestor, verifier, or private graph edge. Campaign Core performs the separately keyed ballot-authorization exchange. KYN never receives the ballot choice.

## Accepted campaign use

The relying party may use release 2.0.0 only for campaign-seeded binding initial-position polls under AIWI change record `MEM-001-BINDING-MEMBER-INITIAL-POSITIONS`. The rule is fixed before opening: seven complete days; quorum `max(3, ceil(20% of eligible members))`; Support or Oppose must exceed half of all current ballots including abstentions; tie, no majority, or insufficient participation creates no position; replacement and private receipts remain available until close; integrity challenges remain open seven days; a passing result creates the official position automatically; and the position expires after 180 days unless superseded or reaffirmed.

No post-result candidate acceptance or veto exists in the normal path. This release does not authorize member-submitted questions, spending, outreach, finance, GUIDE, COMMS, additional external polling, sensitive evidence, verified-Wisconsin claims, affected-public standing, or government action.

## Privacy, security, and recovery

The separate KYN and Campaign Committee databases, signing keys, logs, authority, and encrypted backup repositories remain in force. Participant mutation proofs are body-bound and replay-safe. Public relays must retain strict path and body limits and must not forward browser credentials. Request bodies and participant identifiers do not enter public logs.

Before activation, exact source and image revisions, release-document digests, migration state, listener boundaries, rate and body limits, secret custody, KYN-only encrypted backup, isolated restore, and rollback must pass. Rollback closes ordinary enrollment and member presentations first, retains all required receipts and audit lineage, restores only an exact prior image and verified state, and publishes a bounded correction. Sensitive-evidence enablement remains prohibited.

## Acceptance

Source completion is not activation. Production acceptance requires at least three genuine independently controlled KYN subjects, real exact-version consent, genuine member presentations and ballots, deterministic close and position creation, correlation checks, public limitations, backup, isolated restore, prior-image rollback, and named human acceptance. Fixtures or multiple subjects controlled by one person do not satisfy the human acceptance count.
