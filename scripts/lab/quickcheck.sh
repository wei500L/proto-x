#!/bin/sh
# Run only when no protocol matrix is using the lab: this resets the profile.
set -eu
LAB_REPO=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$LAB_REPO"
LAB_RUN="link-check-$(date -u +%Y%m%dT%H%M%SZ)"
LAB_OUT="$LAB_REPO/.local/lab/$LAB_RUN"
scripts/lab/vm.sh copy tools/lab/netlab.py tools/lab/quickcheck.py protox-lab:/tmp/
scripts/lab/vm.sh shell sudo python3 /tmp/quickcheck.py --output "/tmp/$LAB_RUN"
scripts/lab/vm.sh copy -r "protox-lab:/tmp/$LAB_RUN" "$LAB_OUT"
printf 'Raw validation events and counter snapshots: %s\n' "$LAB_OUT"
