#!/usr/bin/env python3
"""Post-hoc descriptive audit; does not choose or refit a detector.

Recomputes paired cost intervals, startup/steady request latencies and evidence
integrity. The preregistered detector analysis remains in analyze.py.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import numpy as np

import analyze


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def interval_median(values, rng):
    a = np.asarray(values)
    sampled = a[rng.integers(0, len(a), size=(2000, len(a)))]
    # Same nearest-rank p50 convention as the primary analysis.
    medians = np.sort(sampled, axis=1)[:, (len(a)-1)//2]
    return [float(np.quantile(medians, .025)), float(np.quantile(medians, .975))]


def latency(values):
    return {"n": len(values), "p50": analyze.quantile(values, .5),
            "p95": analyze.quantile(values, .95), "p99": analyze.quantile(values, .99),
            "max": max(values, default=0.)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    directory = args.directory
    modes_in_batch = tuple(json.loads((directory / "manifest.json").read_text())["modes"])
    data = []
    evidence = {}
    for path in sorted(directory.glob("*/trial.json")):
        sample = analyze.extract(path.parent)
        sample["events"] = analyze.rows(path.parent / "workload.jsonl")
        data.append(sample)
        evidence[str(path.relative_to(directory))] = digest(path)
    groups = {}
    for sample in data:
        group = groups.setdefault(sample["group"], {})
        if sample["mode"] in group:
            raise ValueError("duplicate group/mode")
        group[sample["mode"]] = sample
    paired = [g for g in groups.values() if set(g) == set(modes_in_batch)]
    rng = np.random.default_rng(20261110)
    modes = {}
    for mode in modes_in_batch:
        samples = [s for s in data if s["mode"] == mode]
        events = [e for s in samples for e in s["events"]]
        first = [e["latency_ms"] for e in events if e["kind"] == "http" and e["status"] == "success" and e["seq"] == 0]
        later = [e["latency_ms"] for e in events if e["kind"] == "http" and e["status"] == "success" and e["seq"] > 0]
        sse_intervals = []
        for sample in samples:
            previous = None
            for event in sample["events"]:
                if event["kind"] != "sse_token":
                    continue
                if previous is not None:
                    source_gap = (event["source_elapsed_ns"] - previous["source_elapsed_ns"]) / 1e6
                    sse_intervals.append({"trial": sample["id"], "seq": event["seq"],
                                          "receive_gap_ms": event["gap_ms"], "source_gap_ms": source_gap,
                                          "receive_minus_source_gap_ms": event["gap_ms"] - source_gap})
                previous = event
        costs = {}
        costs_without_sse = {}
        for counter in ("udp_ingress_bytes", "ipv4_ingress_bytes"):
            relative = [(g[mode]["metrics"][counter] / g[mode]["metrics"]["validated_received_bytes"]) /
                        (g["p0"]["metrics"][counter] / g["p0"]["metrics"]["validated_received_bytes"]) - 1 for g in paired]
            costs[counter] = {"n": len(relative), "median": analyze.quantile(relative, .5),
                              "median_paired_group_bootstrap_95": interval_median(relative, rng),
                              "min": min(relative), "max": max(relative)}
            def checked_content(row):
                return sum(e["bytes"] for e in row["events"]
                           if (e["kind"] == "http" and e["status"] == "success") or
                           (e["kind"] == "download" and e["status"] != "integrity_error"))
            sensitivity = [(g[mode]["metrics"][counter] / checked_content(g[mode])) /
                           (g["p0"]["metrics"][counter] / checked_content(g["p0"])) - 1 for g in paired]
            costs_without_sse[counter] = {"n": len(sensitivity), "median": analyze.quantile(sensitivity, .5)}
        modes[mode] = {
            "sessions": len(samples), "http_all_outcomes": dict(Counter(e["status"] for e in events if e["kind"] == "http")),
            "first_http_success_latency_ms": latency(first), "later_http_success_latency_ms": latency(later),
            "sse_end_outcomes": dict(Counter(e["status"] for e in events if e["kind"] == "sse_end")),
            "download_outcomes": dict(Counter(e["status"] for e in events if e["kind"] == "download")),
            "sse_receive_minus_source_gap_ms": latency([e["receive_minus_source_gap_ms"] for e in sse_intervals]),
            "largest_received_sse_gaps": sorted(sse_intervals, key=lambda e: e["receive_gap_ms"], reverse=True)[:5],
            "sse_payload_validation": {"checked": sum(e["kind"] == "sse_token" and "payload_valid" in e for e in events),
                                       "unchecked_legacy": sum(e["kind"] == "sse_token" and "payload_valid" not in e for e in events)},
            "median_paired_relative_cost": costs,
            "cost_sensitivity_http_download_only": costs_without_sse,
            "mean_per_session_features": {key: float(np.mean([s["features"][key] for s in samples]))
                                          for key in samples[0]["features"]},
        }
    registration = json.loads((directory / "analysis-preregistration.json").read_text())
    heldout = [s for s in data if s["split"] == "heldout"]
    result = {
        "schema": 1, "audited_utc": datetime.now(timezone.utc).isoformat(),
        "kind": "post-hoc descriptive audit; detector model and data split unchanged",
        "complete_groups": len(paired), "sessions": len(data), "modes": modes,
        "evidence": {"max_clock_error_ns": max(s["clock_max_error_ns"] for s in data),
                     "forced_kills": sum(v["forced_kill"] for s in data for v in s["processes"].values()),
                     "native_ech_accepted_sessions": sum(s["metrics"]["native_ech_accepted"] == [True] for s in data if s["mode"] == "native"),
                     "nonzero_owned_process_exits": [{"id": s["id"], "role": role, "exit": v["exit"]}
                                                    for s in data for role, v in s["processes"].items() if v["exit"] != 0],
                     "registration_time": registration["frozen_utc"],
                     "first_heldout_start": min(s["started_utc"] for s in heldout),
                     "registration_precedes_all_heldout": all(registration["frozen_utc"] < s["started_utc"] for s in heldout),
                     "trial_sha256": evidence},
        "limitations": ["group bootstrap conditions on this single-network, single-implementation workload population",
                        "dropping first HTTP here is descriptive; main analysis retains all requests including failures",
                        "timestamps and local registration are auditable metadata, not immutable proof of no prior access"],
    }
    (directory / "audit.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"sessions": len(data), "groups": len(paired), "clock_max_error_ns": result["evidence"]["max_clock_error_ns"]}))


if __name__ == "__main__":
    main()
