#!/bin/sh
# Only for the dedicated, explicitly authorized test VPS. Never use a production
# SSH alias. This script does not alter SSH, NAT mappings, or the firewall.
set -eu
umask 077
if [ "$#" -ne 3 ]; then
  echo 'usage: scripts/deploy-test.sh SSH_CONFIG AUTHORIZED_TEST_HOST_ALIAS PRIVATE_CONFIG_DIR' >&2
  exit 2
fi
cd "$(dirname "$0")/.."
ssh_config=$1
target_host=$2
private_dir=$3
case "$target_host" in ''|-*|*[!a-zA-Z0-9._-]*) echo 'invalid test SSH alias' >&2; exit 2;; esac
test -f "$ssh_config"
test -d "$private_dir"
command -v python3 >/dev/null

ssh_test() {
  ssh -F "$ssh_config" -o BatchMode=yes -o StrictHostKeyChecking=yes \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=3 "$target_host" "$@"
}

bundle_dir=
remote_stage=
remote_started=no
cleanup_local() {
  result=$?
  trap - 0 HUP INT TERM
  if [ -n "$bundle_dir" ]; then rm -rf -- "$bundle_dir"; fi
  # The remote installer owns its recovery once started. Do not remove a stage
  # that may still be in use after an SSH interruption.
  if [ -n "$remote_stage" ] && [ "$remote_started" = no ]; then
    ssh_test "rm -rf -- '$remote_stage'" >/dev/null 2>&1 || \
      printf 'Unfinished upload remains at %s\n' "$remote_stage" >&2
  fi
  exit "$result"
}
trap cleanup_local 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

arch=$(ssh_test 'test "$(id -u)" -eq 0 && uname -m')
PROTOX_BUILD_DIR=${PROTOX_BUILD_DIR:-bin}
case "$arch" in x86_64) binary="$PROTOX_BUILD_DIR/protox-linux-amd64";; aarch64) binary="$PROTOX_BUILD_DIR/protox-linux-arm64";; *) echo 'unsupported test VPS architecture' >&2; exit 1;; esac
test -f "$binary"
mkdir -p .local
bundle_dir=$(mktemp -d .local/deploy-package.XXXXXXXX)

# Python and its TLS/JSON/tar modules are local-only dependencies. Input files
# stay unchanged; only the private deployment copy uses normalized paths.
archive_digest=$(python3 - "$private_dir" "$binary" scripts/protox.service "$bundle_dir" <<'PACKAGE'
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import ssl
import stat
import sys
import tarfile

source = Path(sys.argv[1]).resolve()
destination = Path(sys.argv[4]) / "payload"
destination.mkdir(mode=0o700)

def fail(message):
    raise ValueError(message)

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate JSON field")
        result[key] = value
    return result

def asset_path(raw, field):
    if not isinstance(raw, str) or not raw or any(ch in raw for ch in ("\\", "\n", "\r", "\0")):
        fail("invalid asset path for " + field)
    path = PurePosixPath(raw)
    if path.is_absolute():
        try:
            path = path.relative_to("/opt/proto-x")
        except ValueError:
            try:
                path = path.relative_to(source.as_posix())
            except ValueError:
                fail("asset must be inside the private directory: " + field)
    if not path.parts or ".." in path.parts:
        fail("asset path may not escape the private directory: " + field)
    current = source
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            fail("asset symlinks are not supported: " + field)
    return current

def regular(path, label):
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        fail("asset must be a regular file: " + label)

def copy_file(path, name):
    regular(path, name)
    shutil.copyfile(path, destination / name)

try:
    config_source = asset_path("server.json", "server.json")
    regular(config_source, "server.json")
    config = json.loads(config_source.read_text(encoding="utf-8"), object_pairs_hook=unique_object,
                        parse_constant=lambda value: fail("non-finite JSON number"))
    if not isinstance(config, dict):
        fail("server.json must be an object")
    secret_sources = [config_source]
    for field, name, required in [
        ("cert_file", "server.crt", True), ("key_file", "server.key", True),
        ("token_file", "token", True), ("ech_keys_file", "ech-keys.json", False),
        ("ech_config_file", "ech-config.bin", False), ("ca_file", "ca.crt", False),
    ]:
        raw = config.get(field, "")
        if not isinstance(raw, str):
            fail("asset config fields must be strings: " + field)
        if required and not raw:
            fail("missing required asset field: " + field)
        if raw:
            path = asset_path(raw, field)
            copy_file(path, name)
            config[field] = name
        else:
            candidates = [source / name]
            if field == "ca_file":
                candidates.append(source / "ca.pem")
            present = [item for item in candidates if item.exists() or item.is_symlink()]
            if len(present) > 1:
                fail("set ca_file explicitly when both ca.crt and ca.pem are present")
            path = present[0] if present else None
            if path is not None:
                copy_file(path, name)
        if path is not None and field in ("key_file", "token_file", "ech_keys_file"):
            secret_sources.append(path)

    token = (destination / "token").read_text(encoding="ascii").strip()
    if len(token) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in token):
        fail("token must encode exactly 32 bytes as hexadecimal")
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(str(destination / "server.crt"), str(destination / "server.key"), password="")
    if (destination / "ca.crt").exists():
        tls.load_verify_locations(cafile=str(destination / "ca.crt"))

    cover_raw = config.get("cover_dir", "")
    if not isinstance(cover_raw, str):
        fail("cover_dir must be a string")
    if (config.get("web_listen") or config.get("http3_listen")) and not cover_raw:
        fail("HTTP/2 or HTTP/3 deployment requires cover_dir")
    cover = asset_path(cover_raw, "cover_dir") if cover_raw else source / "cover"
    if cover_raw or cover.exists() or cover.is_symlink():
        if cover.is_symlink() or not cover.is_dir() or cover == source:
            fail("cover_dir must be a separate public directory")
        for private in secret_sources:
            if private == cover or cover in private.parents:
                fail("cover_dir contains a configured private asset")
        (destination / "cover").mkdir(mode=0o700)
        for current, dirs, files in os.walk(cover, followlinks=False,
                                            onerror=lambda error: fail("cannot read the complete public tree")):
            for name in sorted(dirs + files):
                item = Path(current) / name
                relative = item.relative_to(cover)
                if any(ch in str(relative) for ch in ("\n", "\r", "\\")):
                    fail("unsupported public filename")
                if item.is_symlink():
                    fail("public tree symlinks are not supported by deployment")
                target = destination / "cover" / relative
                if item.is_dir():
                    target.mkdir(mode=0o700)
                else:
                    regular(item, "cover file")
                    shutil.copyfile(item, target)
        if cover_raw:
            config["cover_dir"] = "cover"

    copy_file(Path(sys.argv[2]), "protox")
    copy_file(Path(sys.argv[3]), "protox.service")
    (destination / "server.json").write_text(json.dumps(config, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    manifest_path = destination / "package.sha256"
    with manifest_path.open("w", encoding="utf-8") as manifest:
        for item in sorted(destination.rglob("*")):
            if item.is_file() and item != manifest_path:
                digest = hashlib.sha256()
                with item.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                manifest.write(digest.hexdigest() + "  " + item.relative_to(destination).as_posix() + "\n")
    archive = Path(sys.argv[4]) / "package.tar"
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as tar:
        for item in sorted(destination.rglob("*")):
            entry = tar.gettarinfo(str(item), arcname=item.relative_to(destination).as_posix())
            entry.uid = entry.gid = 0
            entry.uname = entry.gname = "root"
            entry.mode = 0o700 if item.is_dir() else 0o600
            if item.is_file():
                with item.open("rb") as stream:
                    tar.addfile(entry, stream)
            else:
                tar.addfile(entry)
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    print(digest.hexdigest())
except (OSError, ValueError, ssl.SSLError) as error:
    print("Deployment package validation failed: " + str(error), file=sys.stderr)
    sys.exit(1)
PACKAGE
)

remote_stage=$(ssh_test 'set -eu
umask 077
test ! -L /opt/proto-x
mkdir -p /opt/proto-x
mktemp -d /opt/proto-x/.upload.XXXXXXXX')
stage_suffix=${remote_stage#/opt/proto-x/.upload.}
case "$remote_stage:$stage_suffix" in /opt/proto-x/.upload.*:*) ;; *) echo 'invalid remote staging path' >&2; remote_stage=; exit 1;; esac
case "$stage_suffix" in ''|*[!a-zA-Z0-9]*) echo 'invalid remote staging suffix' >&2; remote_stage=; exit 1;; esac
scp -F "$ssh_config" -o BatchMode=yes -o StrictHostKeyChecking=yes \
  "$bundle_dir/package.tar" "$target_host:$remote_stage/package.tar"

remote_started=yes
ssh_test 'sh -s --' "$remote_stage" "$archive_digest" <<'REMOTE'
set -eu
umask 077
base=/opt/proto-x
unit=/etc/systemd/system/protox.service
stage=$1
digest=$2
assets='protox server.json server.crt server.key token cover ech-keys.json ech-config.bin ca.crt ca.pem protox.service package.sha256'
lock=no
backup=
backup_ready=no
transaction=no
committed=no

same_process() {
  systemctl is-active --quiet protox.service || return 1
  current_pid=$(systemctl show --property=MainPID --value protox.service) || return 1
  current_restarts=$(systemctl show --property=NRestarts --value protox.service) || return 1
  [ "$current_pid" = "$checked_pid" ] && [ "$current_restarts" = "$checked_restarts" ]
}

check_running() {
  checked_pid=$(systemctl show --property=MainPID --value protox.service) || return 1
  checked_restarts=$(systemctl show --property=NRestarts --value protox.service) || return 1
  case "$checked_pid" in ''|0|*[!0-9]*) return 1;; esac
  case "$checked_restarts" in ''|*[!0-9]*) return 1;; esac
  for check in 1 2 3 4 5; do
    sleep 1
    same_process || return 1
  done
}

restore_backup() {
  # Never replace files while a failed new process may still be using them.
  if [ -f "$unit" ] || [ "$old_active" = yes ]; then
    systemctl stop protox.service || return 1
  fi
  if [ -f "$unit" ]; then systemctl disable protox.service >/dev/null || return 1; fi
  for name in $assets; do rm -rf -- "$base/$name" || return 1; done
  for name in $assets; do
    if [ -e "$backup/files/$name" ] || [ -L "$backup/files/$name" ]; then
      cp -a -- "$backup/files/$name" "$base/$name" || return 1
    fi
  done
  rm -f -- "$unit" || return 1
  if [ "$old_unit" = yes ]; then cp -a -- "$backup/systemd-unit" "$unit" || return 1; fi
  systemctl daemon-reload || return 1
  case "$old_enabled" in
    enabled) systemctl enable protox.service >/dev/null || return 1;;
    enabled-runtime) systemctl enable --runtime protox.service >/dev/null || return 1;;
  esac
  if [ "$old_active" = yes ]; then
    systemctl start protox.service || return 1
    check_running || return 1
  fi
}

cleanup_remote() {
  result=$?
  trap - 0 HUP INT TERM
  set +e
  recovery_failed=no
  if [ "$transaction" = yes ] && [ "$committed" != yes ]; then
    if restore_backup; then
      printf 'Deployment failed; previous package and service state restored. Backup: %s\n' "$backup" >&2
    else
      printf 'AUTOMATIC RESTORE FAILED; recover from %s; stage and lock retained.\n' "$backup" >&2
      result=3
      recovery_failed=yes
    fi
  fi
  if [ -n "$backup" ] && [ "$backup_ready" != yes ]; then rm -rf -- "$backup"; fi
  if [ "$recovery_failed" = no ]; then
    rm -rf -- "$stage"
    if [ "$lock" = yes ]; then
      rm -f "$base/.deploy-lock/pid" "$base/.deploy-lock/stage" "$base/.deploy-lock/backup"
      rmdir "$base/.deploy-lock"
    fi
  fi
  exit "$result"
}
trap cleanup_remote 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

test "$(id -u)" -eq 0
test ! -L "$base"
test ! -L "$base/backups"
test ! -L "$unit"
if ! mkdir "$base/.deploy-lock"; then
  echo 'Another deployment or an interrupted transaction holds /opt/proto-x/.deploy-lock; inspect it before recovery.' >&2
  exit 1
fi
lock=yes
printf '%s\n' "$$" > "$base/.deploy-lock/pid"
printf '%s\n' "$stage" > "$base/.deploy-lock/stage"
printf '%s  %s\n' "$digest" "$stage/package.tar" | sha256sum --check --status
mkdir "$stage/tree"
tar -xf "$stage/package.tar" -C "$stage/tree" --no-same-owner --no-same-permissions
(cd "$stage/tree" && sha256sum --check --status package.sha256)
for name in protox server.json server.crt server.key token protox.service; do test -f "$stage/tree/$name"; done

if ! getent group protox >/dev/null; then groupadd --system protox; fi
if ! getent passwd protox >/dev/null; then
  useradd --system --gid protox --home-dir /nonexistent --shell /usr/sbin/nologin protox
fi
test "$(id -u protox)" -ne 0
chown root:protox "$base"
chmod 750 "$base"
chown -R root:protox "$stage/tree"
find "$stage/tree" -type d -exec chmod 750 {} +
find "$stage/tree" -type f -exec chmod 640 {} +
chmod 755 "$stage/tree/protox"

old_unit=no
if [ -f "$unit" ]; then old_unit=yes; fi
old_active=no
if systemctl is-active --quiet protox.service; then old_active=yes; fi
old_enabled=$(systemctl is-enabled protox.service 2>/dev/null || true)
case "$old_enabled" in enabled|enabled-runtime|disabled|not-found|'') ;; *) echo 'Unsupported pre-existing service enablement; refusing to replace it.' >&2; exit 1;; esac
mkdir -p "$base/backups"
chmod 700 "$base/backups"
backup=$(mktemp -d "$base/backups/$(date -u +%Y%m%dT%H%M%SZ).XXXXXXXX")
mkdir "$backup/files"
for name in $assets; do
  if [ -e "$base/$name" ] || [ -L "$base/$name" ]; then cp -a -- "$base/$name" "$backup/files/$name"; fi
done
if [ "$old_unit" = yes ]; then cp -a -- "$unit" "$backup/systemd-unit"; fi
printf '%s\n' "$old_active" > "$backup/was-active"
printf '%s\n' "$old_enabled" > "$backup/was-enabled"
printf '%s\n' "$old_unit" > "$backup/had-unit"
printf '%s\n' "$assets" > "$backup/managed-assets"
backup_ready=yes
printf '%s\n' "$backup" > "$base/.deploy-lock/backup"
printf 'Complete pre-deployment backup: %s\n' "$backup"

transaction=yes
# Prevent boot activation of a partial package after an uncatchable interruption.
# The previous enablement is recorded and restored if installation fails.
if [ "$old_unit" = yes ] || [ "$old_active" = yes ] || \
   [ "$old_enabled" = enabled ] || [ "$old_enabled" = enabled-runtime ]; then
  systemctl disable protox.service >/dev/null
  systemctl stop protox.service
fi
for name in $assets; do
  rm -rf -- "$base/$name"
  if [ -e "$stage/tree/$name" ]; then mv -- "$stage/tree/$name" "$base/$name"; fi
done
cp -- "$base/protox.service" "$unit"
chown root:root "$unit"
chmod 644 "$unit"
systemctl daemon-reload
systemctl restart protox.service
check_running
systemctl enable protox.service >/dev/null
same_process
committed=yes
printf 'Test deployment stayed active for five seconds with stable MainPID/NRestarts. Backup: %s\n' "$backup"
REMOTE
