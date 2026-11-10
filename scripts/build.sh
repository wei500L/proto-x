#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
PROTOX_BUILD_DIR=${PROTOX_BUILD_DIR:-bin}
mkdir -p "$PROTOX_BUILD_DIR"
go test ./...
go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$PROTOX_BUILD_DIR/protox" ./cmd/protox
go build -trimpath -buildvcs=false -o "$PROTOX_BUILD_DIR/pxbench" ./cmd/pxbench
for arch in arm64 amd64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$PROTOX_BUILD_DIR/protox-linux-$arch" ./cmd/protox
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$PROTOX_BUILD_DIR/pxbench-linux-$arch" ./cmd/pxbench
done
