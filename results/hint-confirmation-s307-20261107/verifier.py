#!/usr/bin/env python3
"""Check retained hint-study provenance, ablation inputs and byte accounting.

Run after summarize.py. Credential values are read locally only for an exact
match scan and are never written to output. No experimental data is changed.
"""
import argparse
import hashlib
import json
from pathlib import Path


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private_scan(roots, private):
    credentials = read(private / "baseline/credentials.json")
    patterns = {v.encode() for v in credentials.values() if isinstance(v, str) and v}
    patterns.add((private / "px/token").read_bytes().strip())
    for key in (private / "px/server.key", private / "baseline/tls-key.pem"):
        body = key.read_bytes().strip()
        patterns.add(body)
        patterns.update(line.strip() for line in body.splitlines()
                        if line.strip() and not line.startswith(b"-----"))
    files = {p for root in roots for p in root.rglob("*") if p.is_file()}
    matching = [str(p) for p in sorted(files) if any(v in p.read_bytes() for v in patterns)]
    return {"pass": not matching, "files": len(files), "credential_patterns": len(patterns),
            "matching_paths": matching,
            "scope": "exact current controlled lab credentials and private key material"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("aggregate", type=Path)
    parser.add_argument("--private", type=Path, default=Path(".local/matrix/stage/private"))
    args = parser.parse_args()
    comparison = read(args.aggregate / "comparison.json")
    rows = comparison["trials"]
    roots = [Path("results") / r["run_id"] for r in comparison["runs"]]
    manifests = [read(p / "manifest.json") for p in roots]
    errors = []
    config_records = []
    for root, manifest in zip(roots, manifests):
        for side in ("client", "server"):
            configs = root / "sanitized-configs/px"
            off = read(configs / f"{side}-px-hints-off.json")
            on = read(configs / f"{side}-px-hints-on.json")
            changed = [k for k in sorted(set(off) | set(on)) if off.get(k) != on.get(k)]
            valid = (changed == ["sparse_redundancy"] and
                     off["sparse_redundancy"] is False and on["sparse_redundancy"] is True)
            config_records.append({"run_id": manifest["run_id"], "side": side,
                                   "changed_fields": changed, "passed": valid})
            if not valid:
                errors.append(f"{manifest['run_id']}/{side}: invalid on/off ablation")
    for row in rows:
        directory = Path(row["raw_path"])
        before, after, delta = (read(directory / name) for name in
                                 ("link-before.json", "link-after.json", "link-delta.json"))
        for side in ("px-client", "px-server"):
            b = next(q for q in before["namespaces"][side]["qdisc"] if q["kind"] == "netem")
            e = next(q for q in after["namespaces"][side]["qdisc"] if q["kind"] == "netem")
            for key, value in delta[side]["qdisc"].items():
                if e[key] - b[key] != value or value < 0:
                    errors.append(f"{row['run_id']}/{row['trial_id']}/{side}: qdisc {key}")
        profile = read(directory / "profile.json")
        expected_loss = 5 if row["profile"] == "loss5-jitter5" else 1
        if (profile["loss_pct_each_direction"] != expected_loss or
                profile["rtt_ms"] != 60 or profile["jitter_ms_each_direction"] != 5 or
                [x["rate_mbps"] for x in profile["directions"]] != [2, 8] or
                not all(x["seed_applied"] for x in profile["directions"])):
            errors.append(f"{row['run_id']}/{row['trial_id']}: profile")
    same = lambda key: all(m[key] == manifests[0][key] for m in manifests)
    px = [r for r in rows if r["variant"].startswith("px-")]
    enabled = [r for r in px if r["sparse_redundancy"]]
    out = {
        "trials": len(rows), "raw_summary_consistent": all(not r["verification_errors"] for r in rows),
        "identical_binary_sets": same("binaries_sha256"),
        "identical_hint_source_file_hashes": all(m["hint_provenance"]["source_files_sha256"] ==
                                                manifests[0]["hint_provenance"]["source_files_sha256"] for m in manifests),
        "identical_matrix_script": same("matrix_script_sha256"),
        "identical_netlab_script": same("netlab_script_sha256"),
        "identical_private_config_hashes": same("private_config_sha256"),
        "all_trial_status_completed": all(r["status"] == "completed" for r in rows),
        "all_px_quic_only_checks_passed": all(r["quic_only_validated"] for r in px),
        "seeds": sorted({r["seed"] for r in rows}),
        "hint_runner_sha256_versions": sorted({m["hint_experiment_script_sha256"] for m in manifests}),
        "config_ablation_checks": config_records,
        "all_config_ablation_checks_passed": all(r["passed"] for r in config_records),
        "all_qdisc_and_profile_checks_passed": not errors,
        "hint_on_server_counters_present": sum(not r["server_hint_counter_log_missing"] for r in enabled),
        "hint_on_client_counters_missing": sum(r["client_hint_counter_log_missing"] for r in enabled),
        "verification_errors": errors,
        "extractor_sha256": comparison["extractor_sha256"], "verifier_sha256": sha(Path(__file__))}
    for key in ("http_success", "http_total", "http_failure", "http_timeout", "http_rejected", "http_censored",
                "echo_success", "echo_total", "echo_failure", "echo_timeout", "echo_rejected", "echo_censored",
                "sse_sequence_errors", "sse_source_errors", "sse_unexpected_ends", "sse_connect_failure",
                "sse_gaps_over_250ms", "sse_gaps_over_1000ms", "sse_terminal_gaps_over_250ms",
                "sse_terminal_gaps_over_1000ms"):
        out[key] = sum(r.get(key, 0) for r in rows)
    out["private_material_scan"] = private_scan(roots + [args.aggregate], args.private)
    (args.aggregate / "verification.json").write_text(json.dumps(out, indent=2) + "\n")
    check_keys = [k for k in out if k.startswith(("identical_", "all_")) or k == "raw_summary_consistent"]
    passed = all(out[k] for k in check_keys) and out["private_material_scan"]["pass"]
    print(json.dumps({"aggregate": str(args.aggregate), "passed": passed,
                      "checks": {k: out[k] for k in check_keys},
                      "errors": errors, "private_material_scan": out["private_material_scan"]}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
