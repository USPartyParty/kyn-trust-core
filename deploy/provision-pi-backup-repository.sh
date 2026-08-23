#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'KYN Pi recovery provisioning failed: %s\n' "$1" >&2
  exit 1
}

[[ "${EUID}" -eq 0 ]] || fail "run as root"
[[ "$#" -eq 1 ]] || fail "usage: $0 /path/to/kyn-backup.pub"
readonly public_key_file="$1"
[[ -f "${public_key_file}" ]] || fail "public key file is absent"
readonly public_key="$(tr -d '\r\n' <"${public_key_file}")"
[[ "${public_key}" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]].*)?$ ]] ||
  fail "public key must be one Ed25519 key"

if ! getent passwd kyn-backup >/dev/null; then
  useradd --system --home-dir /repository --shell /usr/sbin/nologin kyn-backup
fi

install -d -o root -g root -m 0755 /srv/kyn-backup
install -d -o kyn-backup -g kyn-backup -m 0700 /srv/kyn-backup/repository
install -d -o root -g root -m 0755 /etc/ssh/authorized_keys
printf '%s\n' "${public_key}" >/etc/ssh/authorized_keys/kyn-backup
chown root:root /etc/ssh/authorized_keys/kyn-backup
chmod 0600 /etc/ssh/authorized_keys/kyn-backup

cat >/etc/ssh/sshd_config.d/71-kyn-backup-sftp.conf <<'EOF'
Match User kyn-backup
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AuthorizedKeysFile /etc/ssh/authorized_keys/%u
    ChrootDirectory /srv/kyn-backup
    ForceCommand internal-sftp
    DisableForwarding yes
    PermitTTY no
    X11Forwarding no
EOF

sshd -t
systemctl reload ssh
printf 'KYN Pi recovery repository boundary provisioned.\n'
