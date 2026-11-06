#!/bin/sh
# Deploy only to an explicitly supplied, authorized SSH host.
set -eu
if [ "$#" -ne 3 ]; then
  echo 'usage: scripts/deploy-test.sh SSH_CONFIG HOST_ALIAS PRIVATE_CONFIG_DIR' >&2
  exit 2
fi
cd "$(dirname "$0")/.."
ssh_config=$1
target_host=$2
private_dir=$3
case "$target_host" in -*|*[!a-zA-Z0-9._-]*) echo 'invalid SSH alias' >&2; exit 2;; esac
arch=$(ssh -F "$ssh_config" "$target_host" uname -m)
case "$arch" in x86_64) binary=bin/protox-linux-amd64;; aarch64) binary=bin/protox-linux-arm64;; *) echo 'unsupported architecture' >&2; exit 1;; esac
test -f "$binary"
for name in server.json server.crt server.key token; do test -f "$private_dir/$name"; done
ssh -F "$ssh_config" "$target_host" 'umask 077; mkdir -p /opt/proto-x/staging'
scp -F "$ssh_config" "$binary" "$target_host:/opt/proto-x/staging/protox"
scp -F "$ssh_config" "$private_dir/server.json" "$private_dir/server.crt" "$private_dir/server.key" "$private_dir/token" scripts/protox.service "$target_host:/opt/proto-x/staging/"
ssh -F "$ssh_config" "$target_host" 'sh -s' <<'REMOTE'
set -eu
cd /opt/proto-x
stamp=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "backups/$stamp"
chmod 700 backups "backups/$stamp"
for file in protox server.json server.crt server.key token; do
  if [ -f "$file" ]; then cp -p "$file" "backups/$stamp/$file"; fi
done
if [ -f /etc/systemd/system/protox.service ]; then cp -p /etc/systemd/system/protox.service "backups/$stamp/protox.service"; fi
if ! getent passwd protox >/dev/null; then useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin protox; fi
chown root:protox /opt/proto-x
chmod 750 /opt/proto-x
for file in protox server.json server.crt server.key token; do mv "staging/$file" "$file"; done
chown root:protox protox server.json server.crt server.key token
chmod 755 protox
chmod 640 server.json server.crt server.key token
cp staging/protox.service /etc/systemd/system/protox.service
chmod 644 /etc/systemd/system/protox.service
systemctl daemon-reload
systemctl enable protox.service
if ! systemctl restart protox.service; then
  for file in protox server.json server.crt server.key token; do
    if [ -f "backups/$stamp/$file" ]; then cp -p "backups/$stamp/$file" "$file"; fi
  done
  if [ -f "backups/$stamp/protox.service" ]; then cp -p "backups/$stamp/protox.service" /etc/systemd/system/protox.service; fi
  systemctl daemon-reload
  systemctl restart protox.service || true
  exit 1
fi
systemctl --no-pager --full status protox.service
printf 'Backup directory: /opt/proto-x/backups/%s\n' "$stamp"
REMOTE
