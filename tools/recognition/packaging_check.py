#!/usr/bin/env python3
"""Audit public Git files, unpacked tar contents, and Markdown file targets.

Known values are supplied by ignored private JSON files, never printed. This
checks known UTF-8 values and selected key patterns, not all possible secrets.
Tar members are read in memory after validation; no archive is extracted.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
from urllib.parse import unquote, urlsplit


MAX_MEMBER = 64 << 20
MAX_ARCHIVE = 256 << 20
KEY_PATTERNS = {
    "private_key_pem_marker": re.compile(rb"(?m)^-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----\s*$"),
    "aws_access_key_id": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "github_token": re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    "encoded_private_key_json": re.compile(rb'["\'](?:private_key|privateKey|PrivateKey)["\']\s*:\s*["\'][A-Za-z0-9+/_-]{40,}={0,2}["\']'),
}


def git_paths(root, *args):
    data = subprocess.check_output(["git", *args], cwd=root)
    return {os.fsdecode(p) for p in data.split(b"\0") if p}


def load_values(paths):
    values = {}
    for path in paths:
        for item in json.loads(path.read_text())["values"]:
            label, value = item["label"], item["value"]
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", label):
                raise ValueError("private-value label must be a category")
            if not isinstance(value, str) or len(value) < 5:
                raise ValueError("private values require at least five characters")
            values.setdefault(value.encode(), label)
    return [(label, value) for value, label in values.items()]


def public_path(name):
    p = PurePosixPath(name)
    return not p.is_absolute() and ".." not in p.parts and ".local" not in p.parts and "\\" not in name


def markdown_targets(data):
    """Local file destinations from inline links and reference definitions.

    Fenced blocks and inline code are ignored; anchors are not validated. This
    covers this repository's Markdown, not arbitrary HTML or generated links.
    """
    text = data.decode("utf-8", errors="replace")
    lines, fence = [], None
    for line in text.splitlines():
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if marker:
            run = marker.group(1)
            if fence is None:
                fence = run
            elif run[0] == fence[0] and len(run) >= len(fence):
                fence = None
            lines.append("")
        else:
            lines.append("" if fence else re.sub(r"(`+).*?\1", "", line))
    link = re.compile(r'!?\[[^\]\n]*\]\(\s*(<[^>\n]+>|[^\s)]+)(?:\s+["\'][^\n]*?["\'])?\s*\)')
    reference = re.compile(r"^\s{0,3}\[[^\]\n]+\]:\s*(<[^>\n]+>|\S+)")
    for number, line in enumerate(lines, 1):
        matches = list(link.finditer(line))
        ref = reference.match(line)
        if ref:
            matches.append(ref)
        for match in matches:
            yield number, match.group(1).strip("<>")


def inspect(root, values, output, phase):
    root, output = root.resolve(), output.resolve()
    public = git_paths(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    changed = git_paths(root, "diff", "--name-only", "HEAD", "-z") | git_paths(root, "ls-files", "--others", "--exclude-standard", "-z")
    public.discard(str(output.relative_to(root)))
    findings, links, hashes, archives = [], [], {}, []
    bytes_checked, member_count, markdown_count, link_count, file_count = 0, 0, 0, 0, 0

    def redact(value):
        for _, secret in values:
            value = value.replace(secret.decode(), "<redacted>")
        return value

    def issue(path, category, **details):
        findings.append({"path": redact(path), "category": category, **details})

    def scan(name, data):
        nonlocal bytes_checked
        display = redact(name)
        hashes[display] = hashlib.sha256(data).hexdigest()
        bytes_checked += len(data)
        named = os.fsencode(name)
        for label, secret in values:
            count = data.count(secret) + named.count(secret)
            if count:
                issue(name, label, occurrences=count)
        for category, pattern in KEY_PATTERNS.items():
            count = len(pattern.findall(data))
            if count:
                issue(name, category, occurrences=count)

    for name in sorted(public):
        path = root / name
        if not public_path(name):
            issue(name, "nonpublic_inventory_path")
            continue
        if not path.exists() and not path.is_symlink():
            # Tracked deletions are not part of the deliverable.
            continue
        if path.is_symlink():
            file_count += 1
            target = os.readlink(path)
            scan(name, os.fsencode(target))
            resolved = path.resolve()
            if not resolved.is_relative_to(root) or ".local" in resolved.relative_to(root).parts:
                issue(name, "unsafe_public_symlink")
            continue
        if not path.is_file():
            issue(name, "unexpected_nonregular_file")
            continue
        data = path.read_bytes()
        file_count += 1
        scan(name, data)
        if name.endswith((".tar.gz", ".tgz", ".tar")):
            archive = {"path": redact(name), "files_checked": 0, "expanded_bytes": 0}
            archives.append(archive)
            try:
                with tarfile.open(path, "r:*") as tar:
                    for entry in tar:
                        member_name = name + "::" + entry.name
                        if not public_path(entry.name):
                            issue(member_name, "unsafe_archive_member_path")
                            continue
                        if entry.issym() or entry.islnk():
                            target = str(PurePosixPath(entry.name).parent / entry.linkname) if entry.issym() else entry.linkname
                            scan(member_name, entry.linkname.encode())
                            if not public_path(target):
                                issue(member_name, "unsafe_archive_link")
                            continue
                        if entry.isdir():
                            continue
                        if not entry.isfile():
                            issue(member_name, "unsupported_archive_member_type")
                            continue
                        if entry.size > MAX_MEMBER or archive["expanded_bytes"] + entry.size > MAX_ARCHIVE:
                            issue(member_name, "archive_scan_size_limit")
                            break
                        extracted = tar.extractfile(entry)
                        if extracted is None:
                            issue(member_name, "archive_member_read_failed")
                            continue
                        payload = extracted.read(MAX_MEMBER + 1)
                        if len(payload) != entry.size:
                            issue(member_name, "archive_member_size_mismatch")
                        scan(member_name, payload)
                        archive["expanded_bytes"] += len(payload)
                        archive["files_checked"] += 1
                        member_count += 1
            except (tarfile.TarError, OSError):
                issue(name, "archive_read_failed")
        if path.suffix.lower() != ".md":
            continue
        markdown_count += 1
        for line, target in markdown_targets(data):
            try:
                url = urlsplit(target)
                if url.scheme or url.netloc or not url.path:
                    continue
                link_count += 1
                local = (path.parent / unquote(url.path)).resolve()
                category = None
                if not local.is_relative_to(root) or ".local" in local.relative_to(root).parts:
                    category = "nonpublic_local_target"
                elif not local.exists():
                    category = "missing_local_target"
            except (OSError, ValueError):
                category = "invalid_local_target"
            if category:
                links.append({"path": redact(name), "line": line, "target": redact(target), "category": category, "changed_file": name in changed})
    return {
        "schema": 1, "created_utc": datetime.now(timezone.utc).isoformat(), "phase": phase,
        "status": "failed" if findings or links else ("passed" if phase == "final" else "preliminary_passed"),
        "known_values_checked": len(values), "public_files_checked": file_count,
        "archive_regular_files_checked": member_count, "bytes_checked_including_expanded_archives": bytes_checked,
        "archives": archives, "markdown_files_checked": markdown_count, "local_link_targets_checked": link_count,
        "findings": findings, "link_findings": links, "file_sha256": hashes,
        "scope": "Git tracked plus nonignored untracked files, excluding this report; actual files only, including safe tar regular members. Exact supplied UTF-8 values in content/names plus listed key patterns. All public Markdown file destinations; no anchor, external URL, HTML or code-link validation. No guarantee against unknown or transformed secrets. Preliminary runs do not establish final packaging state.",
        "patterns": sorted(KEY_PATTERNS),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--values-private", required=True, action="append", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--phase", required=True, choices=("preliminary", "final"))
    args = parser.parse_args()
    if args.out.exists():
        parser.error("refusing to overwrite a previous audit")
    result = inspect(args.root, load_values(args.values_private), args.out, args.phase)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({key: result[key] for key in ("phase", "status", "known_values_checked", "public_files_checked", "archive_regular_files_checked", "markdown_files_checked", "local_link_targets_checked", "findings", "link_findings")}))
    if result["status"] == "failed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
