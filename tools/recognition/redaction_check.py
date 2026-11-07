#!/usr/bin/env python3
"""Exact-value privacy check; never print the configured private values.

Input is private JSON {"values": [{"label": "category", "value": "..."}]}.
This is a reproducible check of known values, not a general secrets guarantee.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re


def inspect(paths, values):
    known = []
    for item in values:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", item["label"]) or not isinstance(item["value"], str) or len(item["value"]) < 5:
            raise ValueError("known-value labels must be categories and values must have at least five characters")
        known.append((item["label"], item["value"].encode()))
    root = Path(__file__).resolve().parents[2]
    files = set()
    for path in paths:
        for p in ([path] if path.is_file() else path.rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts:
                if p.resolve().is_relative_to((root / ".local").resolve()):
                    raise ValueError("privacy check targets must be public artifacts, not private inputs")
                files.add(p)
    findings, hashes = [], {}
    for path in sorted(files):
        data = path.read_bytes()
        try:
            display = str(path.resolve().relative_to(root))
        except ValueError:
            display = path.name
        for _, value in known:
            display = display.replace(value.decode(), "<redacted>")
        hashes[display] = hashlib.sha256(data).hexdigest()
        for label, value in known:
            if value in data:
                findings.append({"path": display, "category": label, "occurrences": data.count(value)})
        if re.search(rb"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----", data):
            findings.append({"path": display, "category": "private_key_pem_marker"})
    return {"schema": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
            "status": "passed" if not findings else "failed", "known_values_checked": len(known),
            "files_checked": len(files), "findings": findings, "file_sha256": hashes,
            "scope": "exact UTF-8 occurrences of supplied private values plus private-key PEM markers; unknown or transformed secrets are outside this check"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--values-private", required=True, type=Path)
    parser.add_argument("--path", action="append", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("refusing to overwrite a prior privacy check")
    result = inspect(args.path, json.loads(args.values_private.read_text())["values"])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("status", "known_values_checked", "files_checked", "findings")}))
    if result["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
