#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p bin
go test ./...
go build -trimpath -o bin/protox ./cmd/protox
go build -trimpath -o bin/pxbench ./cmd/pxbench
for arch in arm64 amd64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags='-s -w' -o "bin/protox-linux-$arch" ./cmd/protox
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags='-s -w' -o "bin/pxbench-linux-$arch" ./cmd/pxbench
done
