# ADR 0003: Credential And Ballot Separation

- Status: accepted architecture direction

KYN retains subjects, attestations, evidence references, private graph state, and
credential status. A relying party receives a pairwise minimum-disclosure
presentation. A separate authorization exchange emits a ballot-scoped one-time
token/nullifier. The ballot service receives no KYN or campaign identity.
