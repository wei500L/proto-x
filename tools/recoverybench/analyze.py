#!/usr/bin/env python3
"""Summarize observed recovery, retaining timeout/reconnect/censoring denominators.

Unlike a latency-only benchmark, the detector and application clocks are audited
before calculating a fault-to-first-success interval. Every directory is one
independent session; percentiles across sessions do not treat tokens as trials.
"""
import argparse
import json
import math
from pathlib import Path


def read_jsonl(path):
    return [json.loads(s) for s in path.read_text().splitlines() if s.strip()]


def dist(values):
    values = sorted(values)
    if not values:
        return {"n": 0}
    return {"n": len(values), "min": values[0], "median": values[math.ceil(.5*len(values))-1],
            "p95": values[math.ceil(.95*len(values))-1], "max": values[-1]}


def one(path):
    manifest = json.loads((path / "manifest.json").read_text())
    timeline = read_jsonl(path / "timeline.jsonl")
    summary_path = path / "bench.summary.json"
    summary = json.loads(summary_path.read_text()) if summary_path.exists() else {}
    events = read_jsonl(path / "bench.jsonl") if (path / "bench.jsonl").exists() else []
    faults = [e for e in timeline if e["event"] == "fault_start" and e["kind"] != "none"]
    fault = faults[0]["elapsed_ns"] if faults else None
    attaches = [e for e in timeline if e["event"] == "proxy_event" and e.get("role") == "client"
                and e.get("message") == "carrier attached"]
    detaches = [e for e in timeline if e["event"] == "proxy_event" and e.get("role") == "client"
                and e.get("message") == "carrier detached"]
    reconnects = [e for e in attaches if e.get("generation", 0) > 1]
    target_sse = [e for e in timeline if e["event"] == "target_request" and e.get("path") == "/sse"]
    target_echo = [e for e in timeline if e["event"] == "target_accept" and e.get("kind") == "echo"]
    offset = manifest.get("benchmark_epoch_offset_ns")
    timeline_offsets = [e["wall_ns"]-e["elapsed_ns"] for e in timeline if "wall_ns" in e]
    bench_offsets = [e["at_ns"]-e["recorded_elapsed_ns"] for e in events if "at_ns" in e]
    # AtNS is assigned at event construction; some event kinds deliberately
    # describe a previous operation's start. Only instantaneous token/connect
    # events are suitable for checking the epoch bridge.
    bench_offsets = [e["at_ns"]-e["recorded_elapsed_ns"] for e in events
                     if e["kind"] in ("sse_token", "sse_connect", "echo_connect")]
    drift = lambda values: max(values)-min(values) if values else None
    clocks_ok = offset is not None and drift(timeline_offsets) is not None and drift(timeline_offsets) < 1_000_000
    # Benchmark timestamp assignment and recorder locking create bounded local
    # observation delay. Retain its measured spread rather than hide it.
    clocks_ok = clocks_ok and bool(bench_offsets) and drift(bench_offsets) < 5_000_000
    out = {"trial": path.name, "label": manifest["label"], "completed": manifest["completed"],
           "binary_sha256": manifest["protox_sha256"], "harness_sha256": manifest.get("harness_sha256"),
           "fault": manifest["fault"], "direction": manifest["direction"],
           "clock_bridge": {"valid": clocks_ok, "timeline_wall_offset_spread_ns": drift(timeline_offsets),
                            "benchmark_observation_offset_spread_ns": drift(bench_offsets),
                            "benchmark_epoch_offset_ns": offset},
           "client_attach_count": len(attaches), "switch_count": len(reconnects),
           "target_sse_connection_ids": sorted(set(e["connection"] for e in target_sse)),
           "target_echo_connection_ids": sorted(set(e["connection"] for e in target_echo)),
           "target_sse_requests": len(target_sse), "target_echo_accepts": len(target_echo),
           "operations": summary.get("operations"), "sse": summary.get("sse"),
           "echo_connections": summary.get("echo_connections"),
           "download_goodput_mbps": summary.get("download_goodput_mbps"),
           "udp_counts": manifest.get("udp_counts"), "tcp_counts": manifest.get("tcp_counts")}
    if fault is not None:
        t = {"fault_ns": fault}
        candidates = {"detach": detaches, "attach": reconnects,
                      "tcp_connect": [e for e in timeline if e["event"] == "tcp_path_connect"]}
        for name, rows in candidates.items():
            rows = [e for e in rows if e["elapsed_ns"] >= fault]
            if rows:
                t["fault_to_"+name+"_ms"] = (rows[0]["elapsed_ns"]-fault)/1e6
        for kind in ("http", "echo", "sse_token"):
            if not clocks_ok:
                continue
            good = [e for e in events if e["kind"] == kind and e.get("status") == "success"]
            after = [e for e in good if offset+e["recorded_elapsed_ns"] >= fault]
            if after:
                t["fault_to_first_"+kind+"_success_ms"] = (offset+after[0]["recorded_elapsed_ns"]-fault)/1e6
            before = [e for e in good if offset+e["recorded_elapsed_ns"] < fault]
            if after and before:
                t["fault_spanning_"+kind+"_receipt_gap_ms"] = (after[0]["recorded_elapsed_ns"]-before[-1]["recorded_elapsed_ns"])/1e6
        out["timeline"] = t
    if summary:
        sse = summary["sse"]
        out["same_sse_target_continuity"] = (sse["connections"] == 1 and len(target_sse) == 1 and
                                              sse["sequence_errors"] == sse["source_errors"] == sse["unexpected_ends"] == 0)
        out["same_echo_target_continuity"] = (summary["echo_connections"] == len(target_echo) == 1 and
                                               summary["operations"]["echo"]["failure"] == summary["operations"]["echo"]["timeout"] == 0)
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("trials", nargs="+", type=Path)
    p.add_argument("--out", type=Path)
    args = p.parse_args()
    rows = []
    for path in args.trials:
        try:
            rows.append(one(path))
        except Exception as exc:
            rows.append({"trial": path.name, "analysis_error": type(exc).__name__, "detail": str(exc)})
    result = {"trials": rows, "notes": [
        "Each row is one independent proxy session, not an independent token/request.",
        "Proxy log events use receiver timestamps; internal event durations retain their separate session monotonic clock.",
        "Application epoch bridge is used only after local wall/monotonic stability audit; raw clocks and spreads are retained.",
        "TCP relay delays TLS byte chunks, not kernel TCP packets. UDP relay operates on actual datagrams.",
        "Throughput is verified application goodput. Relay byte counts exclude IP/TCP/UDP headers, TCP retransmissions and NIC framing.",
        "A failed or censored request remains in denominators even if later traffic recovers.",
        "Same-target continuity requires one fixture request/accept and one application connection; generated SSE tokens have per-connection sequence numbers."]}
    text = json.dumps(result, indent=2, ensure_ascii=False)+"\n"
    if args.out:
        with args.out.open("x") as f:
            f.write(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
