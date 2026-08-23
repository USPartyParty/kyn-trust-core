#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'KYN backup installation failed: %s\n' "$1" >&2
  exit 1
}

[[ "${EUID}" -eq 0 ]] || fail "run as root"
[[ "$#" -eq 1 ]] || fail "usage: $0 /path/to/prepared-private-config"
readonly private_source="$1"
readonly source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly operator_user="${KYN_OPERATOR_USER:-kcs}"
[[ "${operator_user}" =~ ^[a-z_][a-z0-9_-]*$ ]] || fail "invalid operator user"
id "${operator_user}" >/dev/null 2>&1 || fail "operator user is absent"
for file in backup.conf restic-password id_ed25519 known_hosts; do
  [[ -f "${private_source}/${file}" ]] || fail "missing private input: ${file}"
done
[[ "$(stat -c '%a' "${private_source}/restic-password")" == "600" ]] ||
  fail "staged Restic password must be mode 0600"
[[ "$(stat -c '%a' "${private_source}/id_ed25519")" == "600" ]] ||
  fail "staged SSH key must be mode 0600"

install -d -o root -g root -m 0700 /etc/kyn-backup
install -o root -g root -m 0600 "${private_source}/backup.conf" /etc/kyn-backup/backup.conf
install -o root -g root -m 0600 "${private_source}/restic-password" /etc/kyn-backup/restic-password
install -o root -g root -m 0600 "${private_source}/id_ed25519" /etc/kyn-backup/id_ed25519
install -o root -g root -m 0600 "${private_source}/known_hosts" /etc/kyn-backup/known_hosts
install -d -o root -g root -m 0755 /usr/local/libexec/kyn
install -o root -g root -m 0555 "${source_dir}/kyn-backup-run" /usr/local/libexec/kyn/kyn-backup-run
install -o root -g root -m 0555 "${source_dir}/kyn-restore-test" /usr/local/libexec/kyn/kyn-restore-test
install -o root -g root -m 0555 "${source_dir}/kyn-restore-run" /usr/local/sbin/kyn-restore-run
install -o root -g root -m 0555 "${source_dir}/kyn-restore-latest" /usr/local/sbin/kyn-restore-latest
install -o root -g root -m 0555 "${source_dir}/kyn-rotate-preactivation" /usr/local/sbin/kyn-rotate-preactivation
install -o root -g root -m 0644 "${source_dir}/kyn-backup.service" /etc/systemd/system/kyn-backup.service
install -o root -g root -m 0644 "${source_dir}/kyn-backup.timer" /etc/systemd/system/kyn-backup.timer
readonly sudoers_file="/etc/sudoers.d/90-kyn-backup-operations"
printf '%s ALL=(root) NOPASSWD: /usr/bin/systemctl start kyn-backup.service\n' \
  "${operator_user}" >"${sudoers_file}"
printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/kyn-restore-latest\n' \
  "${operator_user}" >>"${sudoers_file}"
printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/kyn-rotate-preactivation\n' \
  "${operator_user}" >>"${sudoers_file}"
chown root:root "${sudoers_file}"
chmod 0440 "${sudoers_file}"
visudo -cf "${sudoers_file}" >/dev/null

systemd-analyze verify /etc/systemd/system/kyn-backup.service /etc/systemd/system/kyn-backup.timer
systemctl daemon-reload
systemctl enable --now kyn-backup.timer
printf 'KYN backup automation installed; run one manual service before Gate B activation.\n'
