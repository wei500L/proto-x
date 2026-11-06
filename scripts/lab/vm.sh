#!/bin/sh
# Task-private Lima state. Never uses or modifies the user's default instances.
set -eu
LAB_REPO=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
export LIMA_HOME="$LAB_REPO/.local/lab/instances"
LAB_LIMA="$LAB_REPO/.local/lab/lima/bin/limactl"
LAB_NAME=protox-lab
case "${1:-status}" in
  start)
    mkdir -p "$LIMA_HOME"
    chmod 700 "$LIMA_HOME"
    if [ -f "$LIMA_HOME/$LAB_NAME/lima.yaml" ]; then
      exec "$LAB_LIMA" start --tty=false "$LAB_NAME"
    fi
    exec "$LAB_LIMA" start --tty=false --name="$LAB_NAME" "$LAB_REPO/scripts/lab/protox-lima.yaml"
    ;;
  shell)
    shift
    exec "$LAB_LIMA" shell "$LAB_NAME" -- "$@"
    ;;
  copy)
    shift
    exec "$LAB_LIMA" copy "$@"
    ;;
  ssh-config)
    exec "$LAB_LIMA" show-ssh --format=config "$LAB_NAME"
    ;;
  status)
    exec "$LAB_LIMA" list "$LAB_NAME"
    ;;
  stop)
    exec "$LAB_LIMA" stop "$LAB_NAME"
    ;;
  *)
    echo 'usage: vm.sh {start|shell command...|copy source destination|ssh-config|status|stop}' >&2
    exit 2
    ;;
esac
