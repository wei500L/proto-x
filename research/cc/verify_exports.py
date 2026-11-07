#!/usr/bin/env python3
"""Check the portable CC export without building or running its source."""
from __future__ import annotations

import hashlib
import json
import re
import tarfile
from pathlib import Path, PurePosixPath


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def relative_path(root: Path, name: str) -> Path:
    path = PurePosixPath(name)
    require(not path.is_absolute() and ".." not in path.parts,
            f"Nonportable index path: {name}")
    result = root.joinpath(*path.parts)
    require(result.resolve().is_relative_to(root), f"Path escapes root: {name}")
    return result


def main() -> None:
    export = Path(__file__).resolve().parent
    root = export.parents[1]
    index_path = export / "ARTIFACTS.json"
    index = json.loads(index_path.read_text())
    require(index["schema_version"] == 1, "Unknown artifact-index schema")
    indexed = {}
    for entry in index["files"]:
        name = entry["path"]
        require(name not in indexed, f"Duplicate index entry: {name}")
        path = relative_path(root, name)
        require(path.is_file() and not path.is_symlink(), f"Missing regular file: {name}")
        data = path.read_bytes()
        require(len(data) == entry["bytes"], f"Wrong byte count: {name}")
        require(digest(data) == entry["sha256"], f"Checksum mismatch: {name}")
        indexed[name] = entry["sha256"]

    checksum_entries = {}
    for line in (export / "SHA256SUMS").read_text().splitlines():
        checksum, name = line.split("  ", 1)
        require(name not in checksum_entries, f"Duplicate checksum entry: {name}")
        require(re.fullmatch(r"[0-9a-f]{64}", checksum) is not None,
                f"Invalid SHA-256: {name}")
        checksum_entries[name] = checksum
        require(digest(relative_path(root, name).read_bytes()) == checksum,
                f"SHA256SUMS mismatch: {name}")
    expected_checksums = dict(indexed)
    expected_checksums[index_path.relative_to(root).as_posix()] = digest(index_path.read_bytes())
    require(checksum_entries == expected_checksums, "Checksum index has missing or extra entries")

    delivered = {p.relative_to(root).as_posix() for p in export.rglob("*") if p.is_file()}
    expected_delivered = {name for name in indexed if name.startswith("research/cc/")}
    expected_delivered.update({"research/cc/ARTIFACTS.json", "research/cc/SHA256SUMS"})
    require(delivered == expected_delivered, "Export has unindexed or missing files")
    require(not any(p.suffix == ".go" for p in export.rglob("*")),
            "Unexpected loose Go package in export")

    source_files_checked = 0
    test_logs_checked = 0
    for variant in index["variants"].values():
        archive_path = relative_path(root, variant["source_archive"])
        prefix = variant["archive_prefix"].rstrip("/")
        entries = {}
        member_names = set()
        with tarfile.open(archive_path, "r:gz") as archive:
            require(archive.pax_headers.get("comment") == variant["archive_commit"],
                    f"Archive commit marker mismatch: {archive_path.name}")
            for member in archive:
                path = PurePosixPath(member.name)
                require(not path.is_absolute() and ".." not in path.parts
                        and bool(path.parts) and path.parts[0] == prefix,
                        f"Unsafe archive path: {member.name}")
                require(not {".git", ".local", "bin"}.intersection(path.parts),
                        f"Excluded tree in archive: {member.name}")
                require(member.isfile() or member.isdir(),
                        f"Nonregular archive member: {member.name}")
                require(member.name not in member_names, f"Duplicate member: {member.name}")
                member_names.add(member.name)
                if not member.isfile():
                    continue
                data = archive.extractfile(member).read()
                require(not data.startswith((b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")),
                        f"Executable binary in source archive: {member.name}")
                require(re.search(rb"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----", data) is None,
                        f"Private key block in source archive: {member.name}")
                name = PurePosixPath(*path.parts[1:]).as_posix()
                entries[name] = data

        evidence_root = relative_path(root, variant["exported_evidence_root"])
        for path in evidence_root.rglob("*"):
            if not path.is_file():
                continue
            name = path.relative_to(evidence_root).as_posix()
            if name.startswith("replay/"):
                continue  # Build-replay proof was collected after the frozen source commit.
            require(name in entries and path.read_bytes() == entries[name],
                    f"Copied evidence differs from source archive: {path.relative_to(root)}")

        manifest = json.loads(relative_path(root, variant["source_manifest"]).read_text())
        for name, checksum in manifest["source_sha256"].items():
            require(name in entries and digest(entries[name]) == checksum,
                    f"Source-manifest mismatch: {archive_path.name}:{name}")
            source_files_checked += 1

        if "dependency_patch" in variant:
            data = relative_path(root, variant["dependency_patch"]).read_bytes()
            require(entries["patches/quic-go-v0.65.0-cc.patch"] == data,
                    "Standalone dependency patch differs from archived patch")
        if "test_index" in variant:
            for test in json.loads(relative_path(root, variant["test_index"]).read_text()):
                name = test["events"]
                require(name in entries and digest(entries[name]) == test["sha256"],
                        f"Raw test-event hash mismatch: {name}")
                test_logs_checked += 1

        for output in variant["expected_build_outputs"]:
            require(output["included"] is False, "Unexpected claim that a binary is shipped")

    print(f"Verified {len(indexed)} payload files, two source archives, "
          f"{source_files_checked} source hashes and {test_logs_checked} indexed test logs.")
    print("Binary builds, runtime correctness and network performance were not rerun.")


if __name__ == "__main__":
    main()
