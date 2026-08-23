# KYN deployment readiness and KC activation

Status: source-ready candidate as of 2026-07-31; not deployed or activated

This runbook converts KYN-000C source into the first empty, real public beta. It does
not authorize sensitive evidence, fictional live participants, binding or
determining polls, statutory claims, or campaign authority.

## Result of the deployment push

The dark deployment produces a private PostgreSQL database and KYN API on the
Optiplex, with no participant release active. The database has no host port. The API
binds to host loopback and is published only through the separately reviewed HTTPS
ingress. Ordinary enrollment must fail closed until activation.

The deployment bundle provides:

- a pinned Python runtime image and pinned PostgreSQL/pgvector image;
- create-once service-secret provisioning with restrictive ownership and no secret
  values in output;
- a digest-pinned PostgreSQL migration runner that refuses changed applied
  migrations;
- read-only application containers with dropped capabilities, bounded resources,
  an internal database network, a loopback-published API bridge, and capped local
  logs;
- health checks, no production API documentation route, and no database host port;
  and
- a trusted two-stage KC activation client with exact payload review, signed request,
  typed confirmations, response validation, and content-free evidence.

The Optiplex is the designated state host and active deployment target for KYN and
the broader specified state stack. KYN deploys dark and empty on the dedicated
campaign service volume with backup, restore, and disk-monitoring evidence. Replacement
storage and monitored power are the first public financial and polling goal.
Deployment and fundraising advance concurrently, followed by a controlled live-state
migration.

The current integration volume is unencrypted and therefore admits only rotatable
pre-activation service credentials. KC activation, participant enrollment,
credential issuance, and irreplaceable evidence remain disabled until migration to
encrypted replacement storage, rotation of those credentials, proved operator
recovery, and clean restore.

The first live container start proved internal health but exposed no host listener:
marking the API bridge `internal` prevented Docker from realizing the configured
loopback publication. The API bridge is now host-routable only through the explicit
`127.0.0.1:8090` binding. The separate database network remains internal, and
PostgreSQL remains unpublished.

The same live boundary check found that disabling Swagger UI did not disable
FastAPI's raw OpenAPI endpoint. Production configuration now explicitly disables
`/openapi.json` as well as both interactive documentation routes; integration and
development environments retain their schema route for testing.

## Secrets and custody

There are three distinct categories. Never paste any of them into chat.

### Service secrets — generated on the Optiplex

`kyn-provision-secrets` creates the PostgreSQL password/database URL, KYN
presentation-signing seed, pairwise secret, receipt secret, and one-time bootstrap
token directly in the protected state root. Values are never printed or passed in
Compose environment variables. A rerun verifies the files and does not rotate them.

KC does not need to invent or transmit these values. The bootstrap token never
leaves the Optiplex and is removed from active service custody only after activation
and replay-rejection evidence.

### KC participant key — created on KC's workstation

KC chooses a passphrase of at least 16 characters and enters it locally into a
non-echoing prompt. The client generates an Ed25519 key and encrypts its seed with
scrypt plus AES-256-GCM. The encrypted key file and passphrase must not be stored
together. The passphrase is not a server password and cannot be recovered by KYN.

```sh
uv run kyn-activate key-init \
  --output /a/kc-controlled/non-repository/path/kc-kyn.key.json
```

### Backup recovery secret — must be kept off the state host

The first encrypted backup method and recovery custodian must be selected after the
online host inventory confirms the available encrypted destination. Its decryption
material must not live only on the provisional Optiplex. Activation requires a real
restore and a SHA-256 evidence record; a backup job that has never restored does not
pass.

## Exact public release candidate

Release `1.0.0` is staged at these immutable URLs:

- `https://usparty.party/kyn/terms/1.0.0`
- `https://usparty.party/kyn/privacy/1.0.0`
- `https://usparty.party/kyn/notice/1.0.0`
- `https://usparty.party/kyn/security`
- `https://usparty.party/kyn/storage`

The candidate names Five Letter Agency / The Party Party as KYN operator, the Korey
Streich Campaign Committee / AI for Wisconsin as a legally separate relying party,
`kc@uspartyparty.com` as the existing public contact, `provisional_beta` as storage
posture, and sensitive evidence as disabled. The portal independently verifies every
content SHA-256 during its production build.

These pages remain visibly non-effective until the exact KC activation. Publication
for review is not acceptance.

## Deployment and evidence order

1. Confirm the Optiplex is online through Tailscale and record a new read-only host,
   disk-health, mount, container-runtime, firewall, time, and capacity inventory.
2. Confirm the exact state and secret roots are on the dedicated campaign service
   volume, Docker fails closed without that mount, and neither path points to
   personal storage.
3. Build the pinned KYN image from the reviewed source commit; validate the Compose
   expansion and record the image digest.
4. Provision secrets on the host without displaying them.
5. Start PostgreSQL, run the digest-pinned migration, and start KYN on loopback.
6. Verify health, absent API docs, no database host port, no request bodies in logs,
   and failed enrollment while no operator release exists.
7. Configure the exact HTTPS origin and validate the portal relay boundary.
8. Stream an encrypted backup to the accepted destination, restore it into an
   isolated database, compare migration/state facts, and hash the redacted report.
9. Replace the two placeholder hashes in the activation draft with the accepted KC
   designation document and backup-evidence hashes. Review the authority expiry,
   contact, URLs, storage posture, and disabled sensitive-evidence flag.
10. On KC's workstation, inspect and sign the exact draft. Copy only the portable
    signed request to the Optiplex.
11. On the Optiplex, submit the signed request over loopback using the one-time token
    and archive the validated receipt. Neither KC's private key nor its passphrase
    reaches the server.
12. Verify the public release record, initialize KC consent and recovery, register
    only separately accepted claim definitions, and run real empty-to-KC browser
    journeys. Do not seed fictional live data.

## Immediate deployment facts

On 2026-08-01 the Optiplex was reachable through Tailscale and SSH. The read-only
inventory verified active firewall, synchronized time, Docker 29.1.3, approximately
228 GB free in the volume group, no campaign logical volume, and no running
containers. The exact reviewed KYN source is staged on the host with a matching
deployment-file SHA-256. Compose v2.40.3 is installed for the deployment user, the
production model validates, and the exact KYN image builds successfully. No KYN
container, secret, database, or campaign volume exists yet. Interactive
campaign-volume creation, secret provisioning, service start, backup/restore, TLS,
KC key creation, and activation are the immediate deployment work. Do not convert
unperformed observations into passing evidence.

The open-source license is also still an explicit KC decision. Until a `LICENSE`
file is accepted, public source review does not grant copying or redistribution
rights.
