#!/usr/bin/env python3
"""Predeclared session-level detector and cost analysis for shapebench.

Only real encrypted UDP metadata from the business window is used. All five
sessions sharing a workload seed stay together. The held-out groups were
collected later and are never used for scaling, coefficients or thresholds.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path

import numpy as np

MODES = ("native", "p0", "p63", "p127", "p255")


def rows(path):
    return [json.loads(x) for x in path.read_text().splitlines() if x]


def quantile(x, p):
    if not x:
        return 0.
    return float(sorted(x)[max(0, math.ceil(p * len(x)) - 1)])


def auc(y, s):
    pos = np.asarray(s)[np.asarray(y) == 1]
    neg = np.asarray(s)[np.asarray(y) == 0]
    if not len(pos) or not len(neg):
        return None
    diff = pos[:, None] - neg[None, :]
    return float(np.mean((diff > 0) + .5 * (diff == 0)))


def wilson(k, n):
    if n == 0:
        return [0., 1.]
    z = 1.959963984540054
    mean, den = k / n, 1 + z*z/n
    center = (mean + z*z/(2*n)) / den
    width = z * math.sqrt(mean*(1-mean)/n + z*z/(4*n*n)) / den
    return [max(0., center-width), min(1., center+width)]


def logistic(x, y):
    """Fixed L2=1 mean-loss Newton fit; train-only centering and scaling."""
    x, y = np.asarray(x, dtype=float), np.asarray(y, dtype=float)
    if x.ndim != 2 or len(x) != len(y) or not len(x) or set(y) != {0., 1.}:
        raise ValueError("detector training requires both classes and a nonempty matrix")
    if not np.isfinite(x).all():
        raise ValueError("non-finite detector feature")
    mean, scale = x.mean(axis=0), x.std(axis=0)
    scale[scale < 1e-9] = 1.
    z = np.column_stack([np.ones(len(x)), (x - mean) / scale])
    beta = np.zeros(z.shape[1])
    penalty = np.eye(z.shape[1]); penalty[0, 0] = 0
    for _ in range(50):
        # Explicit contractions avoid spurious floating-point status warnings
        # from the local Apple BLAS/NumPy combination, without changing the
        # registered model, regularization or update. Tests check scalar math.
        p = 1 / (1 + np.exp(-np.clip(np.einsum("ij,j->i", z, beta), -40, 40)))
        gradient = np.einsum("ij,i->j", z, p-y) / len(y) + np.einsum("ij,j->i", penalty, beta)
        hessian = np.einsum("ij,i,ik->jk", z, p*(1-p), z) / len(y) + penalty + np.eye(len(beta))*1e-9
        step = np.linalg.solve(hessian, gradient)
        beta -= step
        if not np.isfinite(beta).all():
            raise ValueError("non-finite detector fit")
        if np.linalg.norm(step) < 1e-9:
            break
    return mean, scale, beta


def predict(model, x):
    mean, scale, beta = model
    z = np.column_stack([np.ones(len(x)), (np.asarray(x) - mean) / scale])
    scores = np.einsum("ij,j->i", z, beta)
    if not np.isfinite(scores).all():
        raise ValueError("non-finite detector score")
    return scores  # Ranking and thresholds do not need a calibrated sigmoid.


def features(packets, start, end):
    """No identity, endpoints, timestamps of day, payload or handshake fields."""
    packets = [p for p in packets if p["kind"] == "packet" and start <= p["t_ns"] < end]
    seconds = (end - start) / 1e9
    f = {}
    for direction in ("up", "down"):
        subset = [p for p in packets if p["dir"] == direction]
        sizes = [p["n"] for p in subset]
        times = [p["t_ns"] / 1e6 for p in subset]
        iats = [b-a for a, b in zip(times, times[1:])]
        prefix = direction + "_"
        f[prefix + "packets_per_second"] = len(sizes) / seconds
        f[prefix + "bytes_per_second"] = sum(sizes) / seconds
        f[prefix + "size_mean"] = float(np.mean(sizes)) if sizes else 0.
        f[prefix + "size_std"] = float(np.std(sizes)) if sizes else 0.
        for p in (.1, .5, .9):
            f[prefix + f"size_q{round(p*100)}"] = quantile(sizes, p)
        for maximum in (128, 256, 512, 1000):
            f[prefix + f"size_below_{maximum}"] = sum(n < maximum for n in sizes) / max(1, len(sizes))
        f[prefix + "iat_mean_ms"] = float(np.mean(iats)) if iats else 0.
        f[prefix + "iat_std_ms"] = float(np.std(iats)) if iats else 0.
        f[prefix + "iat_q90_ms"] = quantile(iats, .9)
        f[prefix + "bursts_per_second"] = sum(t > 10 for t in iats) / seconds
        f[prefix + "iat_below_1ms"] = sum(t < 1 for t in iats) / max(1, len(iats))
    f["direction_changes_per_second"] = sum(a["dir"] != b["dir"] for a, b in zip(packets, packets[1:])) / seconds
    return f


def extract(path):
    trial = json.loads((path / "trial.json").read_text())
    if trial.get("status") != "completed":
        raise ValueError("trial did not complete; failure retained separately")
    packets, events = rows(path / "packets.jsonl"), rows(path / "workload.jsonl")
    for name in ("packets.jsonl", "workload.jsonl"):
        if hashlib.sha256((path/name).read_bytes()).hexdigest() != trial["files"][name]:
            raise ValueError("evidence hash mismatch: " + str(path/name))
    pe = next(p["epoch_unix_ns"] for p in packets if p["kind"] == "clock")
    we = next(p["epoch_unix_ns"] for p in events if p["kind"] == "clock")
    ws = next(p["t_ns"] for p in events if p["kind"] == "workload_start")
    done = next(p for p in events if p["kind"] == "workload_end")
    pe_end = next(p for p in packets if p["kind"] == "end")
    clock_error = max(abs(done["wall_unix_ns"] - we - done["t_ns"]),
                      abs(pe_end["wall_unix_ns"] - pe - pe_end["t_ns"]))
    if clock_error > 5e6:
        raise ValueError("same-host wall/monotonic epoch drift exceeds 5ms")
    duration_ns = trial["workload"]["duration_ms"] * 1000000
    begin = we + ws - pe
    # Drop the first 200ms (origin creation) and last 100ms (cancellation).
    f = features(packets, begin + 200000000, begin + duration_ns - 100000000)
    http = [x for x in events if x["kind"] == "http"]
    sse = [x for x in events if x["kind"] == "sse_token"]
    downloads = [x for x in events if x["kind"] == "download"]
    # Legacy helper batches checked SSE JSON/sequence but not the payload
    # string. Keep their declared denominator, with the limitation explicit.
    # A new helper emits payload_valid; explicitly invalid bytes never count.
    valid_received = sum(x["bytes"] for x in http if x["status"] == "success") + sum(x["bytes"] for x in sse if x.get("payload_valid", True)) + sum(x["bytes"] for x in downloads if x["status"] != "integrity_error")
    observed = [p for p in packets if p["kind"] == "packet"]
    forwarded = [p for p in packets if p["kind"] == "forwarded"]
    data = dict(trial, features=f, clock_max_error_ns=clock_error,
                metrics={"http_status": dict(Counter(x["status"] for x in http)),
                         "http_latency_ms": [x["latency_ms"] for x in http if x["status"] == "success"],
                         "http_ttfb_ms": [x["ttfb_ms"] for x in http if x["status"] == "success"],
                         "sse_tokens": len(sse), "sse_gaps_ms": [x["gap_ms"] for x in sse],
                         "sse_sequence_errors": sum(not x["sequence_ok"] for x in sse),
                         "sse_integrity_errors": sum(x["kind"] == "sse_integrity_error" for x in events),
                         "sse_connect_failures": sum(x["kind"] == "sse_connect" and x["status"] != "success" for x in events),
                         "sse_connects": sum(x["kind"] == "sse_connect" for x in events),
                         "sse_unexpected_ends": sum(x["kind"] == "sse_end" and x["status"] != "censored" for x in events),
                         "download_status": dict(Counter(x["status"] for x in downloads)),
                         "download_bytes": sum(x["bytes"] for x in downloads if x["status"] != "integrity_error"),
                         "validated_received_bytes": valid_received,
                         "udp_ingress_bytes": sum(p["n"] for p in observed),
                         "udp_ingress_packets": len(observed),
                         "ipv4_ingress_bytes": sum(p["n"]+28 for p in observed),
                         "udp_forwarded_bytes": sum(p["n"] for p in forwarded),
                         "relay_drop_events": sum(p["kind"].endswith("_drop") for p in packets),
                         "relay_error_events": sum(p["kind"].endswith("_error") for p in packets),
                         "native_ech_accepted": [x["ech_accepted"] for x in events if x["kind"] == "transport"]})
    if valid_received <= 0:
        raise ValueError("empty validated workload")
    return data


def fit_detector(data, mode, feature_names):
    train = [x for x in data if x["split"] == "train" and x["mode"] in ("native", mode)]
    x = [[s["features"][k] for k in feature_names] for s in train]
    y = [int(s["mode"] != "native") for s in train]
    model = logistic(x, y)
    scores = predict(model, x)
    threshold = float(max(s for s, label in zip(scores, y) if label == 0))
    return model, threshold, train


def detector_result(data, mode, names, trained_mode):
    model, threshold, train = fit_detector(data, trained_mode, names)
    test = [x for x in data if x["split"] == "heldout" and x["mode"] in ("native", mode)]
    x = [[s["features"][k] for k in names] for s in test]
    y = [int(s["mode"] != "native") for s in test]
    scores = predict(model, x)
    positives = [s for s, label in zip(scores, y) if label]
    negatives = [s for s, label in zip(scores, y) if not label]
    tp, fp = sum(int(s > threshold) for s in positives), sum(int(s > threshold) for s in negatives)
    by_group = {}
    for trial, score, label in zip(test, scores, y):
        by_group.setdefault(trial["group"], []).append((label, score))
    groups = sorted(by_group)
    rng = np.random.default_rng(803713)
    boot = []
    for _ in range(2000):
        sampled = [row for i in rng.integers(0, len(groups), len(groups)) for row in by_group[groups[i]]]
        boot.append(auc([a for a, b in sampled], [b for a, b in sampled]))
    top = sorted(zip(names, map(float, model[2][1:])), key=lambda v: abs(v[1]), reverse=True)[:8]
    return {"trained_proxy_mode": trained_mode, "tested_proxy_mode": mode,
            "train_sessions": len(train), "heldout_sessions": len(test), "heldout_groups": len(groups),
            "auc": auc(y, scores), "auc_paired_group_bootstrap_95": [float(np.quantile(boot, .025)), float(np.quantile(boot, .975))],
            "threshold": threshold, "threshold_rule": "strictly greater than maximum native training score (empirical training FPR zero)",
            "true_positives": tp, "positives": len(positives), "tpr": tp / len(positives), "tpr_wilson_95": wilson(tp, len(positives)),
            "false_positives": fp, "negatives": len(negatives), "fpr": fp / len(negatives), "fpr_wilson_95": wilson(fp, len(negatives)),
            "largest_standardized_coefficients": top,
            "test_scores": [{"group": t["group"], "mode": t["mode"], "label": label, "score": float(score)} for t, label, score in zip(test, y, scores)]}


def report(data, errors, modes=MODES):
    by_group = {}
    for s in data:
        group = by_group.setdefault(s["group"], {})
        if s["mode"] in group:
            raise ValueError("duplicate session condition in paired group")
        if group:
            sibling = next(iter(group.values()))
            if sibling["workload"] != s["workload"] or sibling["split"] != s["split"]:
                raise ValueError("paired group crosses split or workload")
        group[s["mode"]] = s
    complete = {g: v for g, v in by_group.items() if set(v) == set(modes)}
    # All paired modes and native must be valid; denominators for exclusions
    # remain explicit rather than mixing unmatched workload draws.
    detector_data = [s for s in data if s["group"] in complete]
    if not detector_data:
        raise ValueError("no complete paired groups; cannot estimate a detector")
    if {s["split"] for s in detector_data} != {"train", "heldout"}:
        raise ValueError("complete paired groups must include train and heldout splits")
    names = list(detector_data[0]["features"])
    feature_sets = {"full": names,
                    "size_only": [n for n in names if "size_" in n],
                    "timing_counts_only": [n for n in names if "size_" not in n and "bytes_per_second" not in n]}
    detectors = {}
    for feature_set, selected in feature_sets.items():
        detectors[feature_set] = {
            "features": selected,
            "frozen_p0": [detector_result(detector_data, mode, selected, "p0") for mode in modes[1:]],
            "retrained_each_mode": [detector_result(detector_data, mode, selected, mode) for mode in modes[1:]]}
    metrics = {}
    for mode in modes:
        samples = [s for s in data if s["mode"] == mode]
        counts = Counter()
        for s in samples:
            counts.update(s["metrics"]["http_status"])
        lat = [x for s in samples for x in s["metrics"]["http_latency_ms"]]
        gaps = [x for s in samples for x in s["metrics"]["sse_gaps_ms"]]
        m = {"sessions": len(samples), "http_status": dict(counts),
             "http_latency_ms": {"n": len(lat), "p50": quantile(lat, .5), "p95": quantile(lat, .95), "p99": quantile(lat, .99), "max": max(lat, default=0)},
             "sse_gap_ms": {"n": len(gaps), "p95": quantile(gaps, .95), "p99": quantile(gaps, .99), "max": max(gaps, default=0)}}
        for key in ("sse_tokens", "sse_connects", "sse_connect_failures", "sse_sequence_errors", "sse_integrity_errors", "sse_unexpected_ends", "download_bytes", "validated_received_bytes", "udp_ingress_bytes", "udp_ingress_packets", "ipv4_ingress_bytes", "udp_forwarded_bytes", "relay_drop_events", "relay_error_events"):
            m[key] = sum(s["metrics"][key] for s in samples)
        m["carrier_bytes_per_validated_received_byte"] = m["udp_ingress_bytes"] / m["validated_received_bytes"]
        m["ipv4_bytes_per_validated_received_byte"] = m["ipv4_ingress_bytes"] / m["validated_received_bytes"]
        m["paired_extra_carrier_fraction_vs_p0"] = [v[mode]["metrics"]["udp_ingress_bytes"] / v[mode]["metrics"]["validated_received_bytes"] / (v["p0"]["metrics"]["udp_ingress_bytes"] / v["p0"]["metrics"]["validated_received_bytes"]) - 1 for v in complete.values()]
        m["median_paired_extra_carrier_fraction_vs_p0"] = quantile(m["paired_extra_carrier_fraction_vs_p0"], .5)
        metrics[mode] = m
    return {"schema": 1, "extraction_errors": errors, "valid_sessions": len(data), "complete_paired_groups": len(complete),
            "metrics": metrics, "detectors": detectors,
            "scope": "controlled proxy-vs-native-Go-H3 streaming task; lab evidence only",
            "design": {"model": "fixed L2=1 logistic regression; train-only normalization; Newton solver",
                       "split": "whole paired workload groups; heldout collected after training groups",
                       "window": "business start +200ms through configured end -100ms",
                       "not_features": ["IP", "port", "SNI", "TLS/ECH contents", "certificate", "raw payload", "absolute clock", "group seed", "mode", "filename", "process identity"],
                       "uncertainty": "2000 paired-group bootstrap AUC; Wilson 95% TPR/FPR; does not establish 1% FPR operation",
                       "cost_denominator": "validated HTTP body/download + received SSE payload; legacy helper checked SSE JSON/sequence only, new helper also verifies payload; excludes requests and inner syntax",
                       "line_scope": "UDP payload; IPv4 estimate adds 28 bytes per actual datagram; no Ethernet/NIC headers"}}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory", type=Path)
    p.add_argument("--out", type=Path)
    args = p.parse_args()
    data, errors = [], []
    for path in sorted(args.directory.glob("*/trial.json")):
        try:
            data.append(extract(path.parent))
        except (ValueError, KeyError, OSError, StopIteration) as exc:
            errors.append({"trial": path.parent.name, "error": str(exc)})
    modes = tuple(json.loads((args.directory / "manifest.json").read_text())["modes"])
    result = report(data, errors, modes)
    output = args.out or args.directory / "analysis.json"
    output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    (args.directory / "features.json").write_text(json.dumps([{k: v for k, v in s.items() if k in ("id", "mode", "group", "split", "features", "workload", "clock_max_error_ns")} for s in data], indent=2) + "\n")
    print(json.dumps({"valid_sessions": result["valid_sessions"], "groups": result["complete_paired_groups"], "errors": errors}))


if __name__ == "__main__":
    main()
