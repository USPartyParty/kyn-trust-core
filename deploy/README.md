# KYN public-beta deployment

This bundle deploys KYN dark before any root activation. PostgreSQL has no host
port. The API binds only to host loopback; a separately reviewed TLS reverse proxy
must publish the exact public origin. The public Party Party relay uses a fixed
participant-endpoint allowlist and does not expose bootstrap or operator decisions.

The API bridge is intentionally host-routable so Docker can publish the loopback-only
listener. It is not an `internal` Docker network; isolation at this boundary comes
from the explicit `127.0.0.1` host binding. The separate database network remains
`internal: true` and has no published port.

## Secret process

Never paste a KYN secret into chat, a shell argument, Git, Compose environment, or a
release record. On the state host, copy `production.env.example` to an untracked
mode-`0600` environment file and review only the non-secret paths and issuer. Then
run the create-once tool as root:

```sh
docker compose --env-file /path/to/kyn.production.env \
  -f deploy/compose.production.yml --profile tools run --rm kyn-provision
```

The tool creates the PostgreSQL password, database URL, 32-byte presentation-signing
seed, pairwise secret, receipt secret, and one-time bootstrap token directly beneath
the dedicated state root. It prints no values, repairs exact ownership/modes on a
rerun, refuses empty or conflicting existing files, and never overwrites a valid
secret. The bootstrap token remains mounted only to KYN and the trusted activation
client; delete or archive it outside the host only after the one-time activation and
its replay-rejection check.

KC's participant key is different from these service secrets. Create it with the
trusted activation client on a KC-controlled workstation. Its encrypted key file and
passphrase must not be stored together. KC explicitly reviews and confirms the exact
payload digest. The recommended two-stage flow signs a portable request on KC's
workstation, then submits it on the state host. The portable request contains no
private key or server secret; the one-time bootstrap token never leaves the host and
is never recorded in activation evidence.

```sh
# KC-controlled workstation: create the key once, then inspect/sign the exact draft.
kyn-activate key-init --output /protected/kc-kyn.key.json
kyn-activate inspect --key-file /protected/kc-kyn.key.json --draft activation.json
kyn-activate prepare --key-file /protected/kc-kyn.key.json \
  --draft activation.json --output activation.signed.json

# Copy only activation.signed.json to the state host, then submit over loopback.
kyn-activate submit --api-url http://127.0.0.1:8090 \
  --request activation.signed.json \
  --bootstrap-token-file /protected/secrets/service/bootstrap.token \
  --evidence /protected/evidence/kc-activation.json
```

## Dark deployment

1. Verify the target paths are on the exact dedicated Optiplex campaign service
   volume and Docker cannot start without that mount.
2. Provision secrets and state directories with the command above.
3. Build the exact source commit and record the image digest.
4. Run `docker compose ... up -d kyn-database kyn-migrate kyn-api`.
5. Verify health through loopback and verify ordinary enrollment fails while no
   operator release exists.
6. Configure TLS without request-body logging; expose only the API listener.
7. Perform and hash an encrypted PostgreSQL backup/restore drill.
8. Review the exact release/notice/backup references before activation.

No Compose success, health response, or source test authorizes KC activation or
participant enrollment by itself.

The current unencrypted integration volume is permitted only for the dark, empty
stack and its rotatable pre-activation credentials. KC activation, participant
enrollment, credential issuance, and irreplaceable evidence remain disabled until a
controlled migration to encrypted replacement storage, credential rotation,
operator recovery, and clean restore are accepted.
