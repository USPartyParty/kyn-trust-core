# ADR 0005: Explicit Verification Basis And KC-First Bootstrap

- Status: accepted architecture direction; implemented in KYN-000B source
- Accepted by: KC Streich
- Accepted on: 2026-07-30

Every attestation, credential, presentation, and relying-party manifest identifies
the exact verification basis it uses. Bootstrap voucher, peer attestation,
official-source check, independent review, audit corroboration, and self-assertion
are not interchangeable.

The first live authority may be one explicit, participant-key-controlled, expiring,
publicly labeled KC Streich operator bootstrap. It is non-transitive and may issue
only honestly labeled `bootstrap_vouched` assurance. Later authority comes from
scoped delegation or audited promotion. Popularity, payments, donations, patronage,
engagement, and approval volume confer no authority.

Automated tests use fictional fixtures. A live environment must not be seeded with
fake subjects, attestations, authority, credentials, or audits. KC's bootstrap and
later consenting real participants form the live graph.
