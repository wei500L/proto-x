#!/bin/sh
# Freeze the prototype and explicitly set BOTH endpoints on/off per trial.
set -eu
if [ "${PROTOX_HINT_MATRIX_WRAPPER_FROZEN:-0}" != 1 ]; then
  LAB_HINT_WRAPPER_TEXT=$(cat "$0")
  export PROTOX_HINT_MATRIX_WRAPPER_FROZEN=1
  exec /bin/sh -c "$LAB_HINT_WRAPPER_TEXT" "$0" "$@"
fi
LAB_HINT_REPO=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$LAB_HINT_REPO"
LAB_HINT_RUN=${1:?usage: run-hint-matrix.sh RUN_ID --seed SEED [options...]}
shift
case "$LAB_HINT_RUN" in *[!a-zA-Z0-9_.-]*|'') echo 'invalid run id' >&2; exit 2;; esac
if [ -e "results/$LAB_HINT_RUN" ]; then
  echo 'Refusing to overwrite existing result directory' >&2
  exit 2
fi
python3 - <<'PY'
import hashlib, json, shutil
from pathlib import Path
stage=Path('.local/hint-matrix/stage')
stage.mkdir(parents=True,exist_ok=True)
stage.parent.chmod(0o700)
(stage/'bin').mkdir(exist_ok=True)
base=Path('.local/matrix/stage')
if not (base/'private/px/client-px-priority.json').is_file():
    raise SystemExit('First prepare and validate the ordinary frozen v0.1 matrix')
shutil.copytree(base/'private',stage/'private',dirs_exist_ok=True)
for path in (stage/'private').rglob('*.json'):
    path.write_text(path.read_text().replace('/tmp/pxlab/','/tmp/pxlab-hints/'))
for side in ('server','client'):
    original=json.loads((stage/'private/px'/f'{side}-px-priority.json').read_text())
    original.update(window_bytes=65536,priority=True,adaptive=False,rate_mbps=8 if side=='server' else 2)
    for variant,enabled in (('px-hints-off',False),('px-hints-on',True)):
        cfg=dict(original,sparse_redundancy=enabled)
        (stage/'private/px'/f'{side}-{variant}.json').write_text(json.dumps(cfg,indent=2)+'\n')
for path in (stage/'private').rglob('*'):
    path.chmod(0o700 if path.is_dir() else 0o600)
expected={
    'protox':('.local/hint-matrix/frozen/protox-hints-linux-arm64','0b42f0a8fc63165ed1e9e99d4eb650da6af4e3c097a2a08913fa6e50595d98fe'),
    'pxbench':('.local/matrix/frozen-v01/bin/pxbench-linux-arm64','e01e8df7756512820dc823b7b42f7f4fe58ad952ad3f76f95b7c610f3692353a'),
    'hysteria':('.local/baselines/bin/linux-arm64/hysteria','a68a61a84452ca250ce0368202521965ca9cc9d801a404f1dc9008ac6cf677a7')}
for name,(source,digest) in expected.items():
    source=Path(source)
    if hashlib.sha256(source.read_bytes()).hexdigest()!=digest:
        raise SystemExit('Frozen binary SHA256 mismatch: '+name)
    shutil.copy2(source,stage/'bin'/name)
for name in ('netlab.py','matrix.py','cc_matrix.py','hint_matrix.py'):
    shutil.copy2(Path('tools/lab')/name,stage/name)
parameters=json.loads((base/'public-parameters.json').read_text())
parameters['px'].update(window_bytes=65536,sparse_variants={'px-hints-off':False,'px-hints-on':True},
                        congestion_control='quic-go v0.65.0 default Reno')
(stage/'public-parameters.json').write_text(json.dumps(parameters,indent=2)+'\n')
source_root=Path('.local/hint-prototype')
source_files=[source_root/'go.mod',source_root/'go.sum']
source_files+=sorted((source_root/'internal').rglob('*.go'))
source_files+=sorted((source_root/'cmd').rglob('*.go'))
provenance={'prototype':'sparse delayed datagram copies; same executable in both modes',
            'source_files_sha256':{str(p.relative_to(source_root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files if p.is_file()},
            'expected_sha256':{k:v[1] for k,v in expected.items()},
            'counter_interpretation':'sent_datagrams means accepted by QUIC; first_delivered_bytes means copy delivered first; neither proves physical loss recovery',
            'counter_scope':'session lifetime including warmup; use qdisc deltas for measurement-window external byte costs'}
(stage/'hint-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
PY
go version -m .local/hint-matrix/stage/bin/protox .local/hint-matrix/stage/bin/pxbench \
  .local/hint-matrix/stage/bin/hysteria > .local/hint-matrix/stage/buildinfo.txt
COPYFILE_DISABLE=1 tar --no-xattrs -czf .local/hint-matrix/stage.tar.gz -C .local/hint-matrix/stage .
scripts/lab/vm.sh copy .local/hint-matrix/stage.tar.gz protox-lab:/tmp/pxlab-hints-stage.tar.gz
scripts/lab/vm.sh shell sudo mkdir -p /tmp/pxlab-hints
scripts/lab/vm.sh shell sudo tar -xzf /tmp/pxlab-hints-stage.tar.gz -C /tmp/pxlab-hints
scripts/lab/vm.sh shell sudo chmod 700 /tmp/pxlab-hints/private
LAB_HINT_EXIT=0
scripts/lab/vm.sh shell sudo python3 /tmp/pxlab-hints/hint_matrix.py --run-id "$LAB_HINT_RUN" "$@" || LAB_HINT_EXIT=$?
scripts/lab/vm.sh shell sudo chmod -R a+rX "/tmp/pxlab-hints/results/$LAB_HINT_RUN"
scripts/lab/vm.sh copy -r "protox-lab:/tmp/pxlab-hints/results/$LAB_HINT_RUN" "results/$LAB_HINT_RUN"
printf 'Retained hint matrix results: %s/results/%s\n' "$LAB_HINT_REPO" "$LAB_HINT_RUN"
exit "$LAB_HINT_EXIT"
