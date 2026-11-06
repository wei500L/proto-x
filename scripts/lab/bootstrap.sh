#!/bin/sh
# Install a pinned user-local Lima and create the isolated experiment guest.
set -eu
LAB_REPO=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$LAB_REPO"
if [ "$(uname -sm)" != 'Darwin arm64' ]; then
  echo 'This bootstrap targets macOS arm64. Run tools/lab/netlab.py directly on a disposable Linux VM otherwise.' >&2
  exit 2
fi
mkdir -p .local/lab/lima
chmod 700 .local/lab
if [ ! -x .local/lab/lima/bin/limactl ]; then
  curl -fL --retry 2 'https://github.com/lima-vm/lima/releases/download/v2.3.0/lima-2.3.0-Darwin-arm64.tar.gz' -o .local/lab/lima.tar.gz
  python3 - <<'PY'
import hashlib
from pathlib import Path
p = Path('.local/lab/lima.tar.gz')
assert hashlib.sha256(p.read_bytes()).hexdigest() == 'b7af444bd8f91d3c307477e562f2cf3bd7595d62b9429185e4fa841563578cfc', 'Lima checksum mismatch'
PY
  tar xzf .local/lab/lima.tar.gz -C .local/lab/lima
fi
scripts/lab/vm.sh start
scripts/lab/vm.sh copy tools/lab/netlab.py protox-lab:/tmp/netlab.py
scripts/lab/vm.sh shell sudo python3 /tmp/netlab.py init
scripts/lab/vm.sh shell sudo python3 /tmp/netlab.py profile --up 2 --down 8 --rtt 60 --seed 42
