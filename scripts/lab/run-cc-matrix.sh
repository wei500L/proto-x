#!/bin/sh
# Stage a separate, frozen CC screening batch; reuse only the owned namespaces.
set -eu
if [ "${PROTOX_CC_MATRIX_WRAPPER_FROZEN:-0}" != 1 ]; then
  LAB_CC_WRAPPER_TEXT=$(cat "$0")
  export PROTOX_CC_MATRIX_WRAPPER_FROZEN=1
  exec /bin/sh -c "$LAB_CC_WRAPPER_TEXT" "$0" "$@"
fi
LAB_CC_REPO=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$LAB_CC_REPO"
LAB_CC_RUN=${1:?usage: run-cc-matrix.sh RUN_ID --seed SEED [options...]}
shift
case "$LAB_CC_RUN" in *[!a-zA-Z0-9_.-]*|'') echo 'invalid run id' >&2; exit 2;; esac
if [ -e "results/$LAB_CC_RUN" ]; then
  echo 'Refusing to overwrite existing result directory' >&2
  exit 2
fi
python3 - <<'PY'
import hashlib, json, os, shutil
from pathlib import Path
stage = Path('.local/cc-matrix/stage')
stage.mkdir(parents=True, exist_ok=True)
stage.parent.chmod(0o700)
(stage/'bin').mkdir(exist_ok=True)
base = Path('.local/matrix/stage')
if not (base/'private/px/client-px-priority.json').is_file():
    raise SystemExit('First prepare and validate the ordinary frozen v0.1 matrix')
shutil.copytree(base/'private',stage/'private',dirs_exist_ok=True)
for path in (stage/'private').rglob('*.json'):
    path.write_text(path.read_text().replace('/tmp/pxlab/','/tmp/pxlab-cc/'))
    path.chmod(0o600)
for path in (stage/'private').rglob('*'):
    path.chmod(0o700 if path.is_dir() else 0o600)
window_override = os.environ.get('PROTOX_LAB_CC_WINDOW_BYTES')
if window_override is not None:
    window = int(window_override)
    if window not in (65536, 131072, 262144):
        raise SystemExit('This window diagnostic permits 64, 128, or 256 KiB only')
    for side in ('server','client'):
        path=stage/'private/px'/f'{side}-px-priority.json'
        cfg=json.loads(path.read_text())
        cfg['window_bytes']=window
        path.write_text(json.dumps(cfg,indent=2)+'\n')
expected = {
    'protox': ('.local/matrix/frozen-v01/bin/protox-linux-arm64','28ee62b17791e92dff0f2745c866913d3d500e3b530730102c9f35c977e0e638'),
    'pxbench': ('.local/matrix/frozen-v01/bin/pxbench-linux-arm64','e01e8df7756512820dc823b7b42f7f4fe58ad952ad3f76f95b7c610f3692353a'),
    'protox-cc': ('.local/cc-matrix/frozen/protox-cc-linux-arm64','46b55aa58073753d2a3fa16d76c117ce86692eaca57a2b05e355e52700c45819'),
    'hysteria': ('.local/baselines/bin/linux-arm64/hysteria','a68a61a84452ca250ce0368202521965ca9cc9d801a404f1dc9008ac6cf677a7')}
for name,(source,digest) in expected.items():
    source=Path(source)
    if hashlib.sha256(source.read_bytes()).hexdigest()!=digest:
        raise SystemExit('Frozen binary SHA256 mismatch: '+name)
    shutil.copy2(source,stage/'bin'/name)
for name in ('netlab.py','matrix.py','cc_matrix.py'):
    shutil.copy2(Path('tools/lab')/name,stage/name)
parameters=json.loads((base/'public-parameters.json').read_text())
parameters['px']['window_bytes']=json.loads((stage/'private/px/server-px-priority.json').read_text())['window_bytes']
parameters['experiment']={'window_override_bytes':int(window_override) if window_override is not None else None,
                          'window_override_scope':'isolated diagnostic only; stable inputs and deployed defaults unchanged'}
(stage/'public-parameters.json').write_text(json.dumps(parameters,indent=2)+'\n')
source_root=Path('.local/cc-prototype')
source_files=[source_root/'go.mod',source_root/'go.sum']
source_files+=sorted((source_root/'internal/carrier').glob('*.go'))
source_files+=sorted((source_root/'internal/hycc').rglob('*'))
provenance={'hycc_source':json.loads((source_root/'internal/hycc/SOURCE.json').read_text()),
            'source_files_sha256':{str(p.relative_to(source_root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files if p.is_file()},
            'fork':'github.com/apernet/quic-go v0.63.1-0.20261004180939-a10df75c260c',
            'fork_delta':'CC installed after app authentication; explicit QUIC v1; same scheduler/session/config semantics',
            'path_migration_limitation':'fork may reset CC to Reno on migration; not exercised in static-path screening',
            'default_expected_sha256':{k:v[1] for k,v in expected.items()}}
(stage/'cc-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
PY
go version -m .local/cc-matrix/stage/bin/protox .local/cc-matrix/stage/bin/pxbench \
  .local/cc-matrix/stage/bin/protox-cc .local/cc-matrix/stage/bin/hysteria \
  > .local/cc-matrix/stage/buildinfo.txt
COPYFILE_DISABLE=1 tar --no-xattrs -czf .local/cc-matrix/stage.tar.gz -C .local/cc-matrix/stage .
scripts/lab/vm.sh copy .local/cc-matrix/stage.tar.gz protox-lab:/tmp/pxlab-cc-stage.tar.gz
scripts/lab/vm.sh shell sudo mkdir -p /tmp/pxlab-cc
scripts/lab/vm.sh shell sudo tar -xzf /tmp/pxlab-cc-stage.tar.gz -C /tmp/pxlab-cc
scripts/lab/vm.sh shell sudo chmod 700 /tmp/pxlab-cc/private
LAB_CC_EXIT=0
scripts/lab/vm.sh shell sudo python3 /tmp/pxlab-cc/cc_matrix.py --run-id "$LAB_CC_RUN" "$@" || LAB_CC_EXIT=$?
scripts/lab/vm.sh shell sudo chmod -R a+rX "/tmp/pxlab-cc/results/$LAB_CC_RUN"
scripts/lab/vm.sh copy -r "protox-lab:/tmp/pxlab-cc/results/$LAB_CC_RUN" "results/$LAB_CC_RUN"
printf 'Retained CC matrix results: %s/results/%s\n' "$LAB_CC_REPO" "$LAB_CC_RUN"
exit "$LAB_CC_EXIT"
