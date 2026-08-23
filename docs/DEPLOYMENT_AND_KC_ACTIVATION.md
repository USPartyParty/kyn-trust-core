# KYN deployment readiness and KC activation

Status: dark deployment reconciled 2026-08-23; Gate B package accepted but not activated

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

The Optiplex is the designated state host. The actual dark deployment uses the
dedicated `/srv/aiwi-services/kyn` state and secret roots. The API is healthy on
`127.0.0.1:8090`, PostgreSQL has no host port, the database is empty, documentation
routes are absent, and the operator-release endpoint fails closed.

The state volume is unencrypted. For Gate B only, KC accepted a one-subject
provisional exception: exactly one KC-controlled `bootstrap_vouched` subject may be
activated after a separate encrypted KYN backup repository on the Pi and a clean
isolated restore pass. Sensitive evidence, ordinary enrollment, additional subjects,
verified-Wisconsin claims, binding/determining polls, and durable-production claims
remain prohibited. Backup failure, inability to restore, unexpected exposure, or
loss of operator/relying-party separation stops the beta. Replacement storage and
monitored power remain the funded migration path rather than a prerequisite for this
single-subject exception.

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

### Backup recovery secret — separate KYN custody

Gate B uses a KYN-only encrypted Restic repository on the Pi with credentials
independent from the Campaign Committee repository. KC/FLA is the initial recovery
custodian. The repository password and transport key must not live only on the
Optiplex or share campaign backup credentials. Activation requires a real isolated
restore and a SHA-256 evidence record; a backup job that has never restored does not
pass.

The reviewed source provides:

- `deploy/provision-pi-backup-repository.sh`: root-only creation of the separate
  `kyn-backup` SFTP chroot and key boundary on the Pi;
- `deploy/install-kyn-backup.sh`: root-only Optiplex credential and systemd
  installation;
- `deploy/kyn-backup-run`: revision-bound database/secret backup with KYN/FLA tags
  and content-free evidence; and
- `deploy/kyn-restore-test` and `deploy/kyn-restore-run`: Restic lookup plus
  isolated no-network PostgreSQL restore, migration/count comparison, and
  secret-archive catalog verification.

Prepare the SSH key, Restic password, pinned host key, and `backup.conf` outside the
repository. Provision the Pi with only the public key. On the Optiplex, install the
private inputs under `/etc/kyn-backup`, start one manual `kyn-backup.service`, record
its snapshot ID, and run:

```sh
sudo /usr/local/sbin/kyn-restore-run FULL_SNAPSHOT_ID
```

Do not enable Gate B merely because a snapshot exists; the isolated restore evidence
must report `passed`.

## Exact accepted Gate B release package

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

KC accepted these exact pages operationally for the bounded Gate B package, together
with Apache License 2.0 and the FLA-operator/separate-Campaign-Committee relying-party
boundary. This is not independent legal advice. The pages remain visibly
non-effective until the signed KC activation succeeds.

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

## Reconciled deployment facts

On 2026-08-23 the dark API and database are healthy. The API is loopback-only,
PostgreSQL is unpublished, `/docs` and `/openapi.json` return `404`, and the
operator-release endpoint returns `503`. The database has zero state and command
rows. Applied migration `0001_kyn_000b_state.sql` matches reviewed SHA-256
`9e02acee4fbd16946973e8e17b274deab749b3b71c8d4fda188164e91e592ba2`.
Release pages are public and enrollment is closed.

Apache License 2.0, the operational release package, the one-subject provisional
exception, and separate encrypted Pi recovery direction are accepted. Remaining
activation work is the revision-labeled image rebuild, KYN-only backup repository,
isolated restore, exact operator/relying-party and KC designation records, activation
draft hashes, service-secret rotation, KC key creation, signed request, receipt,
replay rejection, and redacted evidence. No missing observation is recorded as
passed.
