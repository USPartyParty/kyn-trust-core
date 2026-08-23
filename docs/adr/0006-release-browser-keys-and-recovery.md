# ADR 0006: Release-gated browser keys, accountable recovery, and privacy actions

- Status: accepted for KYN-000C source implementation
- Date: 2026-07-30

## Decision

Ordinary KYN participation is authenticated by a pseudonymous Ed25519 key generated
in the participant's browser. The portal stores a re-imported non-exportable
`CryptoKey` in IndexedDB and sends only body-bound signatures and the public key. A
Keycloak account is neither required nor silently linked to the KYN subject.

Enrollment is disabled until the accountable operator activates an exact public
release record. The release discloses provisional or durable storage, binds exact
notice/terms/privacy versions, records backup evidence, and refuses sensitive
evidence in KYN-000C.

Recovery uses a high-entropy participant-held secret. KYN stores only its SHA-256
commitment and the durable command store retains only request digests. A matching
secret and proof from the replacement key open a pending case; an explicitly scoped
operator must decide it. Approval rotates only the subject-key binding and consumes
the commitment.

Privacy requests are signed by the subject key and processed by an explicitly
scoped authority. Export remains subject-scoped. Correction, withdrawal, and
deletion prospectively invalidate derived trust. Public receipts and necessary
pseudonymous decision tombstones are not rewritten.

## Consequences

The portal server cannot impersonate participants merely by possessing its own
session or Keycloak credentials. Clearing browser storage without the recovery code
can permanently lose control. IndexedDB does not protect against a compromised
browser origin, so CSP, dependency discipline, HTTPS, incident response, and clear
recovery instructions remain required. Recovery is accountable rather than fully
automatic and must be monitored for coercion, collusion, and operator compromise.
