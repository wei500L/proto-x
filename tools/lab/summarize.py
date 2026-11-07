#!/usr/bin/env python3
"""Extract per-trial comparisons without pooling seeds or dropping failures.

Only writes derived files into --out. Raw manifests and events stay untouched.
Checks event populations and nearest-rank latency summaries before reporting.
"""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path


FROZEN_PX_RENO = "28ee62b17791e92dff0f2745c866913d3d500e3b530730102c9f35c977e0e638"
RENO_REFERENCE = "https://github.com/quic-go/quic-go/blob/v0.65.0/internal/ackhandler/sent_packet_handler.go#L155-L163"


def read(path):
    return json.loads(path.read_text()) if path.exists() else {}


def percentile(values, p):
    return sorted(values)[max(0, math.ceil(len(values) * p) - 1)] if values else 0


def extract(run_dir, manifest, trial):
    directory = run_dir / trial["trial_id"]
    summary = read(directory / "events.summary.json")
    row = {"run_id": manifest["run_id"], "trial_id": trial["trial_id"],
           "raw_path": str(directory), "variant": trial["variant"],
           "profile": trial["profile"], "seed": trial["seed"],
           "status": trial["status"], "error": trial.get("error", ""),
           "stage": trial["stage"], "warmup_s": trial["warmup_s"],
           "configured_duration_s": trial["duration_s"],
           "background_workers": trial["background_workers"],
           "background_mbps_source_budget_per_worker": trial.get("background_mbps_source_budget"),
           "px_window_bytes": manifest.get("config_parameters", {}).get("px", {}).get("window_bytes"),
           "px_congestion_control": trial.get("congestion_control", "quic-go v0.65.0 default Reno" if
               trial["variant"] in ("px-priority", "px-fifo", "px-adaptive") and
               manifest["binaries_sha256"].get("protox") == FROZEN_PX_RENO else "") if trial["variant"].startswith("px-") else "",
           "protocol_binary": trial.get("protocol_binary", ""),
           "protocol_binary_sha256": manifest["binaries_sha256"].get(trial.get("protocol_binary", "")),
           "controller_log_validation_passed": trial.get("controller_validation", {}).get("passed"),
           "sparse_redundancy": trial.get("sparse_redundancy"),
           "quic_only_validated": trial.get("quic_only_validated"),
           "protox_sha256": manifest["binaries_sha256"].get("protox"),
           "benchmark_sha256": manifest["binaries_sha256"].get("pxbench")}
    checks = []
    if "hint_activity" in trial:
        row["hint_activity"] = trial["hint_activity"]
        for role, activity in trial["hint_activity"]["roles"].items():
            row[f"{role}_hint_counter_record_count"] = len(activity["counter_records"])
            row[f"{role}_hint_counter_log_missing"] = activity["missing_counter_log"]
            for key in ("sent_datagrams", "skipped_copies", "first_delivered_bytes", "duplicate_data_bytes"):
                row[f"{role}_hint_last_{key}"] = (activity.get("last_record") or {}).get(key)
    events = []
    event_path = directory / "events.jsonl"
    if event_path.exists():
        events = [json.loads(line) for line in event_path.read_text().splitlines() if line]
    raw = defaultdict(Counter)
    for event in events:
        raw[event["kind"]][event.get("status", "unspecified")] += 1
    if summary:
        duration = summary["duration_seconds"]
        row["duration_seconds"] = duration
        for name, op in summary.get("operations", {}).items():
            for field in ("total", "success", "failure", "timeout", "censored", "rejected", "connection_attempts"):
                row[f"{name}_{field}"] = op.get(field, 0)
            if sum(raw[name].values()) != op["total"]:
                checks.append(f"{name}: raw total disagrees with summary")
            for status in ("success", "failure", "timeout", "censored", "rejected"):
                if raw[name][status] != op.get(status, 0):
                    checks.append(f"{name}: {status} count disagrees")
            for field, source in (("latency_ms", "successful_latency_ms"),
                                  ("scheduled_latency_ms", "successful_scheduled_latency_ms"),
                                  ("ttfb_ms", "successful_ttfb_ms")):
                stat = op.get(source, {})
                vals = [x[field] for x in events if x["kind"] == name and x.get("status") == "success" and field in x]
                for quantile, p in (("p50", .5), ("p95", .95), ("p99", .99)):
                    row[f"{name}_{field}_{quantile}"] = stat.get(quantile)
                    if quantile in stat and not math.isclose(percentile(vals, p), stat[quantile], abs_tol=1e-8):
                        checks.append(f"{name}: {field} {quantile} disagrees")
        sse = summary.get("sse", {})
        for key, value in sse.items():
            if isinstance(value, dict):
                for subkey, subvalue in value.items():
                    row[f"sse_{key}_{subkey}"] = subvalue
            else:
                row[f"sse_{key}"] = value
        if sum(raw["sse_token"].values()) != sse.get("tokens", 0):
            checks.append("SSE raw token count disagrees")
        tokens = [x for x in events if x["kind"] == "sse_token"]
        for field in ("receive_gap_ms", "source_gap_ms", "excess_gap_ms", "source_generation_delay_ms"):
            stat = sse.get(field, {})
            values = ([max(0, x.get(field, 0)) for x in tokens if "source_gap_ms" in x]
                      if field == "excess_gap_ms" else [x[field] for x in tokens if field in x])
            if len(values) != stat.get("n", 0):
                checks.append(f"SSE {field}: raw population disagrees")
            for quantile, p in (("p50", .5), ("p95", .95), ("p99", .99)):
                if quantile in stat and not math.isclose(percentile(values, p), stat[quantile], abs_tol=1e-8):
                    checks.append(f"SSE {field}: {quantile} disagrees")
        for threshold in (250, 1000):
            if sum(x.get("receive_gap_ms", 0) > threshold for x in tokens) != sse.get(f"gaps_over_{threshold}ms", 0):
                checks.append(f"SSE >{threshold}ms gap count disagrees")
        for key in ("download_validated_bytes", "download_goodput_mbps", "upload_server_confirmed_bytes",
                    "upload_confirmed_goodput_mbps", "echo_connections"):
            row[key] = summary.get(key, 0)
        row["benchmark_config"] = summary.get("config", {})
        link = read(directory / "link-delta.json")
        outer_bytes = 0
        for side in ("client", "server"):
            data = link.get("px-" + side, {})
            for key, value in data.get("qdisc", {}).items():
                row[f"{side}_qdisc_{key}"] = value
            outer_bytes += data.get("qdisc", {}).get("bytes", 0)
            row[f"{side}_all_namespace_tcp_retrans_segments_includes_loopback"] = data.get("namespace_tcp_retrans_segments_includes_loopback")
        row["outer_qdisc_bytes_both_directions"] = outer_bytes
        row["outer_qdisc_mbps_both_directions"] = outer_bytes * 8 / duration / 1e6
        download_bytes = summary.get("download_validated_bytes", 0)
        row["all_outer_bytes_per_download_byte"] = outer_bytes / download_bytes if download_bytes else None
        resource = read(directory / "resource-summary.json")
        for role, values in resource.get("roles", {}).items():
            for key in ("rss_peak_bytes", "rss_mean_bytes", "cpu_percent_one_core", "sampled_seconds"):
                row[f"{role}_{key}"] = values.get(key)
    elif trial["status"] == "completed":
        checks.append("Completed trial is missing workload summary")
    row["raw_event_counts_by_status"] = {kind: dict(counts) for kind, counts in raw.items()}
    row["verification_errors"] = checks
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runs", nargs="+", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    rows, manifests = [], []
    for run_dir in args.runs:
        manifest = read(run_dir / "manifest.json")
        manifests.append({key: manifest[key] for key in (
            "run_id", "created_utc", "binaries_sha256", "matrix_script_sha256",
            "netlab_script_sha256", "parameters", "config_parameters")})
        for key in ("cc_experiment_script_sha256", "private_config_sha256", "cc_provenance",
                    "hint_experiment_script_sha256", "redactor_module_sha256", "hint_provenance"):
            if key in manifest:
                manifests[-1][key] = manifest[key]
        for trial in read(run_dir / "index.json"):
            rows.append(extract(run_dir, manifest, trial))
    output = {"source": "Linux VM packet-level emulation; per-trial estimates; no seed pooling",
              "extractor_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "px_reno_source_reference": RENO_REFERENCE,
              "notes": ["All attempts, failed runs, statuses and censoring retained.",
                        "Percentiles describe successful operations only and are nearest-rank.",
                        "Outer qdisc bytes include interactive traffic; ratio to download bytes is not pure protocol overhead.",
                        "Namespace TCP retransmissions include loopback sockets and do not measure QUIC retransmission.",
                        "Identical loss seeds do not assign identical loss to each protocol's application messages."],
              "runs": manifests, "trials": rows}
    (args.out / "comparison.json").write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n")
    fields = list(dict.fromkeys(key for row in rows for key in row if not isinstance(row[key], (dict, list))))
    with (args.out / "comparison.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    failures = [row for row in rows if row["verification_errors"]]
    print(json.dumps({"trials": len(rows), "statuses": dict(Counter(x["status"] for x in rows)),
                      "event_verification_failures": [{"trial_id": x["trial_id"], "errors": x["verification_errors"]} for x in failures],
                      "output": str(args.out)}, ensure_ascii=False))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
