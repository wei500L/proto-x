#!/usr/bin/env python3
"""Validate complete workload populations and summarize zero-capture relay costs.

Per-trial numbers stay separate. No failed trial or run-end censoring is removed.
"""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path


def read_json(path):
    return json.loads(path.read_text()) if path.exists() else {}


def read_events(path):
    return [json.loads(x) for x in path.read_text().splitlines() if x] if path.exists() else []


def quantile(values, q):
    return sorted(values)[max(0, math.ceil(q * len(values)) - 1)] if values else 0


def check_distribution(errors, label, summary, values):
    expected = {"n": len(values), "p50": quantile(values, .5), "p95": quantile(values, .95),
                "p99": quantile(values, .99), "max": max(values, default=0),
                "mean": sum(values) / len(values) if values else 0}
    for key, value in expected.items():
        if not math.isclose(summary.get(key, 0), value, rel_tol=1e-10, abs_tol=1e-8):
            errors.append(f"{label}.{key}: summary differs from raw events")


def analyze(directory):
    trial = read_json(directory / "trial.json")
    summary = read_json(directory / "events.summary.json")
    events = read_events(directory / "events.jsonl")
    relay = read_events(directory / "relay-events.jsonl")
    errors = []
    row = {key: trial.get(key) for key in ("trial_id", "case", "network", "padding", "repeat", "order", "status", "error")}
    populations = defaultdict(Counter)
    for event in events:
        populations[event["kind"]][event.get("status", "unspecified")] += 1
    row["raw_populations"] = {key: dict(values) for key, values in populations.items()}
    if not summary:
        errors.append("missing workload summary")
    if len([x for x in events if x["kind"] == "run_start"]) != 1:
        errors.append("expected exactly one run_start")
    if len([x for x in events if x["kind"] == "run_end"]) != 1:
        errors.append("expected exactly one run_end")
    if any(x.get("run_id") != row["trial_id"] for x in events):
        errors.append("raw run_id mismatch")
    elapsed = [x["recorded_elapsed_ns"] for x in events]
    if any(b < a for a, b in zip(elapsed, elapsed[1:])):
        errors.append("raw elapsed times moved backwards")
    row["actual_benchmark_seconds"] = summary.get("duration_seconds")
    for name, stats in summary.get("operations", {}).items():
        raw = [x for x in events if x["kind"] == name]
        if len(raw) != stats["total"]:
            errors.append(f"{name} total differs")
        if sum(stats.get(status, 0) for status in ("success", "failure", "timeout", "censored", "rejected")) != stats["total"]:
            errors.append(f"{name} full status denominator differs")
        for status in ("success", "failure", "timeout", "censored", "rejected"):
            row[f"{name}_{status}"] = stats.get(status, 0)
            if populations[name][status] != stats.get(status, 0):
                errors.append(f"{name} {status} count differs")
        row[f"{name}_total"] = stats["total"]
        row[f"{name}_connection_attempts"] = stats["connection_attempts"]
        if sum(x.get("attempts", 0) for x in raw) != stats["connection_attempts"]:
            errors.append(f"{name} connection attempts differ")
        successful = [x for x in raw if x.get("status") == "success"]
        distributions = (("latency_ms", "successful_latency_ms", successful),
                         ("scheduled_latency_ms", "successful_scheduled_latency_ms", [x for x in successful if x.get("scheduled_ns", 0)]),
                         ("ttfb_ms", "successful_ttfb_ms", [x for x in successful if x.get("ttfb_ms", 0) > 0]))
        for raw_key, summary_key, relevant in distributions:
            check_distribution(errors, name + "." + raw_key, stats[summary_key], [x.get(raw_key, 0) for x in relevant])
            for key in ("n", "p50", "p95", "p99", "max"):
                row[f"{name}_{raw_key}_{key}"] = stats[summary_key][key]
    for name in ("http", "echo", "download_end", "upload"):
        if populations.get(name) and name not in summary.get("operations", {}):
            errors.append(f"raw {name} population absent from summary")
    tokens = [x for x in events if x["kind"] == "sse_token"]
    ends = [x for x in events if x["kind"] == "sse_end"]
    tails = [x for x in events if x["kind"] == "sse_run_tail"]
    sse = summary.get("sse", {})
    checks = {"tokens": len(tokens), "sequence_errors": sum(x.get("status") != "success" for x in tokens),
              "connections": populations["sse_connect"]["success"],
              "connect_failure": sum(x["kind"] == "sse_connect" and x.get("status") not in ("success", "censored") for x in events),
              "source_errors": sum(x["kind"] == "sse_source_error" for x in events),
              "unexpected_ends": sum(x.get("status") != "censored" for x in ends),
              "max_terminal_gap_ms": max((x.get("terminal_gap_ms", 0) for x in ends), default=0),
              "run_tail_gap_ms": tails[-1].get("terminal_gap_ms", 0) if tails else 0}
    for threshold in (250, 1000):
        checks[f"gaps_over_{threshold}ms"] = sum(x.get("receive_gap_ms", 0) > threshold for x in tokens)
        checks[f"excess_over_{threshold}ms"] = sum(x.get("excess_gap_ms", 0) > threshold for x in tokens if x.get("receive_gap_ms", 0) > 0)
        checks[f"terminal_gaps_over_{threshold}ms"] = sum(x.get("terminal_gap_ms", 0) > threshold for x in ends)
    for key, value in checks.items():
        if not math.isclose(sse.get(key, 0), value, rel_tol=1e-10, abs_tol=1e-8):
            errors.append(f"SSE {key} differs")
        row["sse_" + key] = sse.get(key, 0)
    receiving = [x for x in tokens if x.get("receive_gap_ms", 0) > 0]
    sourced = [x for x in receiving if x.get("source_gap_ms", 0) > 0]
    for key, population in (("receive_gap_ms", receiving), ("source_gap_ms", sourced),
                            ("excess_gap_ms", sourced), ("source_generation_delay_ms", tokens)):
        stats = sse.get(key, {})
        check_distribution(errors, "sse." + key, stats, [x.get(key, 0) for x in population])
        for subkey in ("n", "p50", "p95", "p99", "max"):
            row["sse_" + key + "_" + subkey] = stats.get(subkey)
    download = sum(x.get("bytes", 0) for x in events if x["kind"] == "download_end")
    if download != summary.get("download_validated_bytes", 0):
        errors.append("download byte population differs")
    row["download_validated_bytes"] = download
    row["download_goodput_mbps"] = summary.get("download_goodput_mbps", 0)
    duration = summary.get("duration_seconds", 0)
    if duration <= 0 or not math.isclose(download * 8 / duration / 1e6, row["download_goodput_mbps"], rel_tol=1e-10, abs_tol=1e-8):
        errors.append("download goodput differs or invalid run duration")
    echo_connections = populations["echo_connect"]["success"]
    row["echo_connections"] = echo_connections
    if echo_connections != summary.get("echo_connections", 0):
        errors.append("echo connection population differs")
    incoming = {name: sum(x.get("bytes", 0) for x in events if x["kind"] == name and x.get("status") == "success")
                for name in ("http", "echo", "sse_token")}
    application_bytes = download + sum(incoming.values())
    row["validated_received_application_bytes"] = application_bytes
    row["validated_received_byte_components"] = {"download_including_censored_tail": download, **incoming}
    if len([x for x in relay if x["kind"] == "capture_started"]) != 1 or len([x for x in relay if x["kind"] == "capture_stopped"]) != 1:
        errors.append("relay capture missing unique start/stop")
    if any(x["kind"] in ("udp_datagram", "tcp_bytes", "private_udp_mapping") for x in relay):
        errors.append("published zero-capture evidence contains payload/mapping event")
    counts = [x for x in relay if x["kind"] == "flow_counts"]
    if not counts:
        errors.append("missing relay counts")
    for direction in ("client_to_server", "server_to_client"):
        selected = [x for x in counts if x["direction"] == direction]
        byte_count = sum(x["bytes"] for x in selected)
        chunk_count = sum(x["chunks"] for x in selected)
        row[direction + "_carrier_bytes"] = byte_count
        key = "udp_datagrams" if row["network"] in ("h3", "quic") else "tcp_read_chunks"
        row[direction + "_" + key] = chunk_count
        if byte_count <= 0:
            errors.append(direction + " has no counted traffic")
        if any(x["captured_bytes"] != 0 or x["captured_chunks"] != 0 for x in selected):
            errors.append("relay captured payload despite zero limits")
    starts, stops = [x for x in relay if x["kind"] == "capture_started"], [x for x in relay if x["kind"] == "capture_stopped"]
    row["relay_interval_seconds"] = (stops[0]["elapsed_ns"] - starts[0]["elapsed_ns"]) / 1e9 if starts and stops else None
    row["carrier_bytes_both_directions"] = sum(x["bytes"] for x in counts)
    row["bidirectional_carrier_bytes_per_validated_received_application_byte"] = row["carrier_bytes_both_directions"] / application_bytes if application_bytes else None
    row["relay_flow_count"] = sum(x["kind"] == "flow_started" for x in relay)
    row["relay_diagnostic_events"] = [x for x in relay if x["kind"] not in ("capture_started", "capture_stopped", "flow_started", "flow_counts")]
    resources = read_events(directory / "resources.jsonl")
    for role, values in trial.get("resources", {}).items():
        row[role + "_rss_sampled_peak_kib"] = values.get("rss_sampled_peak_kib")
        row[role + "_resource_samples"] = values.get("samples")
        samples = [x for x in resources if x.get("role") == role]
        if len(samples) != values.get("samples") or max((x["rss_kib"] for x in samples), default=None) != values.get("rss_sampled_peak_kib"):
            errors.append(f"{role} RSS summary differs from raw samples")
        if role in ("client", "server", "relay", "benchmark", "origin") and not samples:
            errors.append(f"{role} has no resource samples")
    for role, values in trial.get("processes", {}).items():
        if values.get("forced_kill"):
            errors.append(f"{role} required forced kill")
        if values.get("exit_code") != 0:
            errors.append(f"{role} exited {values.get('exit_code')}")
    for filename, hashes in trial.get("evidence_files", {}).items():
        path = directory / filename
        if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != hashes["published_sha256"]:
            errors.append(f"{filename}: published evidence hash differs")
    row["validation_errors"] = errors
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("study", type=Path)
    args = parser.parse_args()
    manifest = read_json(args.study / "manifest.json")
    index = read_json(args.study / "index.json")
    rows = [analyze(args.study / item["trial_id"]) for item in index]
    study_errors = []
    if manifest.get("binaries_sha256") != manifest.get("frozen_sha256_after"):
        study_errors.append("frozen executable/relay hashes changed or post-run hashes missing")
    if not manifest.get("all_planned_trials_attempted") or manifest.get("completed_trials") != len(rows):
        study_errors.append("study incomplete; retained rows are not the complete planned matrix")
    comparisons = []
    for network in ("h2", "h3"):
        for repeat in sorted({x["repeat"] for x in rows}):
            groups = {x["padding"]: x for x in rows if x["network"] == network and x["repeat"] == repeat}
            if 0 not in groups or 127 not in groups:
                continue
            plain, padded = groups[0], groups[127]
            key = "bidirectional_carrier_bytes_per_validated_received_application_byte"
            comparisons.append({"network": network, "repeat": repeat, "padding0_trial": plain["trial_id"],
                "padding127_trial": padded["trial_id"], "padding0_status": plain["status"], "padding127_status": padded["status"],
                "validation_passed": not plain["validation_errors"] and not padded["validation_errors"],
                "normalized_carrier_cost_change_percent": ((padded[key] / plain[key]) - 1) * 100 if plain[key] and padded[key] else None})
    result = {"schema": 1, "pilot": manifest.get("pilot"), "study": manifest.get("label"),
              "summarizer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "study_validation_errors": study_errors,
              "binaries_sha256": manifest.get("binaries_sha256"), "trials": rows, "padding_comparisons": comparisons,
              "notes": ["No pooling across repeats; retain failed trials and full status denominators.",
                  "Carrier/application ratio includes both carrier directions but denominator only validated received application bytes.",
                  "The denominator excludes requests, inner HTTP/SSE syntax and timestamps; ratio is not pure protocol overhead.",
                  "Capture interval includes startup, prebenchmark idle, workload and shutdown; not solely steady-state traffic.",
                  "Loopback latency is diagnostic, not evidence for impaired-network superiority."]}
    (args.study / "comparison.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    fields = list(dict.fromkeys(k for row in rows for k, value in row.items() if not isinstance(value, (list, dict))))
    with (args.study / "comparison.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    errors = [{"trial": x["trial_id"], "errors": x["validation_errors"]} for x in rows if x["validation_errors"]]
    print(json.dumps({"trials": len(rows), "statuses": dict(Counter(x["status"] for x in rows)),
                      "validation_errors": errors, "study_validation_errors": study_errors,
                      "padding_comparisons": comparisons}, ensure_ascii=False))
    return 1 if errors or study_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
