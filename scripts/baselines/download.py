#!/usr/bin/env python3
"""Fetch pinned official baseline binaries; validate release API SHA-256 values."""
import argparse
import concurrent.futures
import hashlib
import io
import json
import os
from pathlib import Path
import urllib.request
import zipfile

ASSETS = [
    ("xray", "darwin-arm64", "v26.10.31", "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-macos-arm64-v8a.zip", "0a05dca3bd311b0bc5a89c7ce56350cab1e829e131e4b2bcd48eb304fac07e9a"),
    ("xray", "linux-amd64", "v26.10.31", "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-64.zip", "e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214"),
    ("xray", "linux-arm64", "v26.10.31", "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-arm64-v8a.zip", "1811c8f1da0c3b6dc707ebaf1c8390e987ba39859a8f0a7aadd8526157f2ec8d"),
    ("hysteria", "darwin-arm64", "app/v2.13.0", "https://github.com/HyNetworks/hysteria/releases/download/app/v2.13.0/hysteria-darwin-arm64", "c8c3589239ce4ecf335c07a3f6ec11b3ef8fbdfe9e5a5ea0ef8ba8ce50d2bb90"),
    ("hysteria", "linux-amd64", "app/v2.13.0", "https://github.com/HyNetworks/hysteria/releases/download/app/v2.13.0/hysteria-linux-amd64", "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691"),
    ("hysteria", "linux-arm64", "app/v2.13.0", "https://github.com/HyNetworks/hysteria/releases/download/app/v2.13.0/hysteria-linux-arm64", "a68a61a84452ca250ce0368202521965ca9cc9d801a404f1dc9008ac6cf677a7"),
]


def fetch(asset, root):
    name, platform, version, url, expected = asset
    dst = root / platform / name
    dst.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "PROTO-X-baseline-research"})
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read()
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError(f"checksum mismatch for {url}: {actual}")
    if url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            binary = archive.read("xray")
    else:
        binary = data
    temporary = dst.with_suffix(".tmp")
    temporary.write_bytes(binary)
    temporary.chmod(0o755)
    temporary.replace(dst)
    return {"name": name, "platform": platform, "version": version, "url": url,
            "asset_sha256": expected, "binary_sha256": hashlib.sha256(binary).hexdigest(),
            "binary_bytes": len(binary), "path": str(dst)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path(".local/baselines/bin"))
    parser.add_argument("--platform", choices=["all", "darwin-arm64", "linux-amd64", "linux-arm64"], default="all")
    args = parser.parse_args()
    assets = [a for a in ASSETS if args.platform == "all" or a[1] == args.platform]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        manifest = list(executor.map(lambda a: fetch(a, args.out), assets))
    manifest_path = args.out / "manifest.json"
    previous = json.loads(manifest_path.read_text()) if manifest_path.exists() else []
    replaced = {(x["name"], x["platform"]) for x in manifest}
    merged = [x for x in previous if (x["name"], x["platform"]) not in replaced] + manifest
    manifest_path.write_text(json.dumps(merged, indent=2) + "\n")
    for item in manifest:
        print(f"verified {item['name']} {item['version']} {item['platform']} ({item['binary_bytes']} bytes)")


if __name__ == "__main__":
    main()
