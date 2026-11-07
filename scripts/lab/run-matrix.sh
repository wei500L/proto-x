#!/bin/sh
# Stage binaries/private configs and run a matrix in the dedicated VM. Keep
# discovery and withheld confirmation stages separate and retain all failures.
set -eu
# Freeze the wrapper text before a long SSH command. Editing this file during
# development must not change the shell's subsequent read offset mid-run.
if [ "${PROTOX_MATRIX_WRAPPER_FROZEN:-0}" != 1 ]; then
  LAB_WRAPPER_TEXT=$(cat "$0")
  export PROTOX_MATRIX_WRAPPER_FROZEN=1
  exec /bin/sh -c "$LAB_WRAPPER_TEXT" "$0" "$@"
fi
LAB_REPO=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$LAB_REPO"
LAB_BINS=${PROTOX_LAB_BIN_DIR:-bin}
LAB_RUN=${1:?usage: run-matrix.sh RUN_ID [matrix.py options...]}
shift
case "$LAB_RUN" in *[!a-zA-Z0-9_.-]*|'') echo 'invalid run id' >&2; exit 2;; esac
if [ -e "results/$LAB_RUN" ]; then
  echo 'Refusing to overwrite existing result directory' >&2
  exit 2
fi
mkdir -p .local/matrix/stage/bin .local/matrix/stage/private
chmod 700 .local/matrix
if [ ! -f .local/matrix/stage/private/px/client.json ]; then
  bin/protox init -dir .local/matrix/stage/private/px -host 10.203.0.2 -tls-port 14443 -quic-port 14443
fi
python3 scripts/baselines/configure.py --server 10.203.0.2 \
  --out .local/matrix/stage/private/baseline --server-directory /tmp/pxlab/private/baseline \
  --reality-target 127.0.0.1:39443 --reality-sni protox-baseline.test \
  --allow-test-cidr 127.0.0.1/32
python3 - <<'PY'
import copy, json
from pathlib import Path
stage = Path('.local/matrix/stage')
px = stage / 'private/px'
for side in ('server', 'client'):
    base = json.loads((px / (side+'.json')).read_text())
    base['rate_mbps'] = 8 if side == 'server' else 2
    base['allow_private_targets'] = side == 'server'
    base['test_rotate_seconds'] = 0
    for variant in ('px-priority', 'px-fifo', 'px-adaptive'):
        cfg = copy.deepcopy(base)
        cfg['priority'] = variant != 'px-fifo'
        cfg['adaptive'] = variant == 'px-adaptive'
        (px / f'{side}-{variant}.json').write_text(json.dumps(cfg,indent=2)+'\n')
base = stage / 'private/baseline'
for path in base.glob('hysteria-client-*.json'):
    cfg = json.loads(path.read_text())
    cfg['tls']['ca'] = '/tmp/pxlab/private/baseline/tls-cert.pem'
    path.write_text(json.dumps(cfg,indent=2)+'\n')
for side in ('server', 'client'):
    cfg = json.loads((base / f'hysteria-{side}-brutal.json').read_text())
    (base / f'hysteria-{side}-brutal8.json').write_text(json.dumps(cfg,indent=2)+'\n')
    # Hysteria's parser accepts integer quantities. 1500 kbps = 1.5 Mbps.
    cfg['bandwidth']['up'] = '6 mbps' if side == 'server' else '1500 kbps'
    cfg['bandwidth']['down'] = '1500 kbps' if side == 'server' else '6 mbps'
    (base / f'hysteria-{side}-brutal6.json').write_text(json.dumps(cfg,indent=2)+'\n')
public = {'px': {'server_rate_mbps':8,'client_rate_mbps':2,'window_bytes':65536,
                 'variants':['priority=true,adaptive=false','priority=false,adaptive=false','priority=true,adaptive=true'],
                 'transport':'QUIC preferred with authenticated TLS fallback'},
          'xray': {'version':'26.10.31','protocol':'VLESS+REALITY+Vision','mux':False,'fingerprint':'chrome',
                   'target':'owned TLS1.3 cover on loopback','inner_application':'HTTPS TLS with verified owned CA'},
          'hysteria': {'version':'2.13.0','profiles':['BBR standard','BBR conservative','Brutal8/2Mbps','Brutal6/1.5Mbps'],
                       'brutal_disable_loss_compensation':False,'fastOpen':False},
          'addresses': {'client':'10.203.0.1','server':'10.203.0.2','origin':'127.0.0.1'},
          'secrets':'omitted; regenerate private configs with provided scripts'}
(stage / 'public-parameters.json').write_text(json.dumps(public,indent=2)+'\n')
for path in (stage / 'private').rglob('*'):
    path.chmod(0o700 if path.is_dir() else 0o600)
PY
cp "$LAB_BINS/protox-linux-arm64" .local/matrix/stage/bin/protox
cp "$LAB_BINS/pxbench-linux-arm64" .local/matrix/stage/bin/pxbench
cp .local/baselines/bin/linux-arm64/xray .local/matrix/stage/bin/xray
cp .local/baselines/bin/linux-arm64/hysteria .local/matrix/stage/bin/hysteria
cp .local/baselines/bin/linux-arm64/tlscover .local/matrix/stage/bin/tlscover
cp tools/lab/netlab.py .local/matrix/stage/netlab.py
cp tools/lab/matrix.py .local/matrix/stage/matrix.py
go version -m .local/matrix/stage/bin/protox .local/matrix/stage/bin/pxbench \
  .local/matrix/stage/bin/xray .local/matrix/stage/bin/hysteria .local/matrix/stage/bin/tlscover \
  > .local/matrix/stage/buildinfo.txt
COPYFILE_DISABLE=1 tar --no-xattrs -czf .local/matrix/stage.tar.gz -C .local/matrix/stage .
scripts/lab/vm.sh copy .local/matrix/stage.tar.gz protox-lab:/tmp/pxlab-stage.tar.gz
scripts/lab/vm.sh shell sudo mkdir -p /tmp/pxlab
scripts/lab/vm.sh shell sudo tar -xzf /tmp/pxlab-stage.tar.gz -C /tmp/pxlab
scripts/lab/vm.sh shell sudo chmod 700 /tmp/pxlab/private
LAB_EXIT=0
scripts/lab/vm.sh shell sudo python3 /tmp/pxlab/matrix.py --run-id "$LAB_RUN" "$@" || LAB_EXIT=$?
scripts/lab/vm.sh shell sudo chmod -R a+rX "/tmp/pxlab/results/$LAB_RUN"
mkdir -p results
scripts/lab/vm.sh copy -r "protox-lab:/tmp/pxlab/results/$LAB_RUN" "results/$LAB_RUN"
printf 'Retained matrix results: %s/results/%s\n' "$LAB_REPO" "$LAB_RUN"
exit "$LAB_EXIT"
