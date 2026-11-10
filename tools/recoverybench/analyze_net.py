#!/usr/bin/env python3
"""Audit packet-netlab recovery without confusing in-flight replies with recovery.

One row is an independently restarted proxy session. Clock bridges are accepted
only after comparing monotonic/wall offsets; event delivery delay is retained.
No classification, token-level significance, or field-DPI conclusion is implied.
"""
import argparse
import datetime as dt
import json
import re
from pathlib import Path
import statistics


def read(path, default=None):
    return json.loads(path.read_text()) if path.exists() else default


def jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []


def stamp(value):
    # Python 3.9 rejects Go's nine-digit RFC3339 fraction. Preserve it exactly
    # instead of rounding an epoch-sized floating point timestamp.
    fraction=re.search(r"\.(\d+)(?=Z|[+-]\d\d:\d\d$)",value)
    nanos=0
    if fraction:
        nanos=int((fraction.group(1)+"000000000")[:9])
        value=value[:fraction.start()]+value[fraction.end():]
    return int(dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())*1_000_000_000+nanos


def spread(values):
    return max(values)-min(values) if values else None


def one(path):
    trial = read(path/"trial.json")
    summary = read(path/"events.summary.json", {})
    events = jsonl(path/"events.jsonl")
    proxies = read(path/"proxy-events.json", [])
    target = jsonl(path/"target-events.jsonl")
    faults = read(path/"fault-events.json", [])
    launch = next((e for e in faults if e["event"] == "workload_launch"), None)
    end = next((e for e in faults if e["event"] == "workload_exit"), None)
    fault = next((e for e in faults if e["event"] == "fault_install_begin"), None)
    installed = next((e for e in faults if e["event"] == "fault_installed"), None)
    proxy_client = [e for e in proxies if e["role"] == "client"]
    attaches = [e for e in proxy_client if e.get("msg") == "carrier attached"]
    offsets = [e["wall_ns"]-e["mono_ns"] for e in faults if "mono_ns" in e]
    offsets += [e["observed_wall_ns"]-e["observed_mono_ns"] for e in proxies]
    bench_offsets = [e["at_ns"]-e["recorded_elapsed_ns"] for e in events
                     if e["kind"] in ("sse_token", "sse_connect", "echo_connect")]
    epoch = stamp(summary["started_utc"]) if summary else None
    epoch_delta = statistics.median(bench_offsets)-epoch if bench_offsets and epoch else None
    clock_ok = (bool(offsets and bench_offsets and epoch) and spread(offsets) < 2e6
                and spread(bench_offsets) < 5e6 and abs(epoch_delta) < 5e6)
    row = {k:trial.get(k) for k in ("trial_id", "variant", "profile", "seed", "status", "error")}
    row.update(operations=summary.get("operations"), sse=summary.get("sse"),
               echo_connections=summary.get("echo_connections"),
               download_goodput_mbps=summary.get("download_goodput_mbps"),
               link=read(path/"link-delta.json"), startup_link=read(path/"link-startup-warmup-delta.json"),
               resource=read(path/"resource-summary.json"),
               clock_bridge=dict(valid=clock_ok, vm_offset_spread_ns=spread(offsets),
                                 bench_offset_spread_ns=spread(bench_offsets), bench_epoch_wall_ns=epoch,
                                 observed_bench_epoch_delta_ns=epoch_delta),
               attach_count=len(attaches), client_switches=max(0,len(attaches)-1),
               preparation_count=sum(e.get("event")=="prepare_start" for e in proxy_client),
               canceled_preparations=sum(e.get("event")=="prepare_cancel" for e in proxy_client),
               commit_count=sum(e.get("event")=="commit" for e in proxy_client),
               delivery_proof_count=sum(e.get("event")=="delivery_proof" for e in proxy_client),
               delivery_proof_age_ms=dist(e["age_ns"]/1e6 for e in proxy_client if e.get("event")=="delivery_proof" and "age_ns" in e),
               ech_observations=[{k:e[k] for k in ("event", "carrier", "ech_required", "ech_accepted", "tls_version", "alpn") if k in e}
                                 for e in proxy_client if e.get("event") in ("tls_ready", "prepare_ready")])
    if launch and end:
        measured_target = [e for e in target if launch["wall_ns"] <= e["wall_ns"] <= end["wall_ns"]]
        sse_ids = [e["connection"] for e in measured_target if e["event"] == "target_request" and e.get("path") == "/sse"]
        echo_ids = [e["connection"] for e in measured_target if e["event"] == "target_accept" and e.get("kind") == "echo"]
        row["target"] = dict(sse_requests=len(sse_ids), sse_connections=sorted(set(sse_ids)),
                             echo_accepts=len(echo_ids), echo_connections=sorted(set(echo_ids)),
                             small_requests=sum(e["event"] == "target_request" and e.get("path") == "/small" for e in measured_target))
        if summary:
            sse, echo = summary["sse"], summary["operations"].get("echo", {})
            row["same_sse_target_continuity"] = (sse["connections"] == len(sse_ids) == 1 and sse["tokens"] > 0 and
                    sse["sequence_errors"] == sse["source_errors"] == sse["unexpected_ends"] == 0)
            row["same_echo_target_continuity"] = (summary["echo_connections"] == len(echo_ids) == 1 and
                    echo.get("success",0) > 0 and echo.get("failure",0) == echo.get("timeout",0) == 0)
    if fault:
        origin = fault["mono_ns"]
        detail = {"install_bracket_ms": (installed["mono_ns"]-origin)/1e6 if installed else None}
        after = [e for e in proxy_client if e["observed_mono_ns"] >= origin]
        selected = {}
        for name in ("suspected", "prepare_start", "prepare_ready", "commit", "dead_timeout", "dial_start", "tls_ready", "activation_ready"):
            selected[name] = next((e for e in after if e.get("event") == name), None)
        selected["attach"] = next((e for e in after if e.get("msg") == "carrier attached"), None)
        selected["detach"] = next((e for e in after if e.get("msg") == "carrier detached"), None)
        if selected["attach"]:
            selected["first_progress"] = next((e for e in after if e.get("event") == "first_progress"
                    and e.get("generation") == selected["attach"].get("generation")), None)
        detail["client_events_ms_from_fault_install_begin"] = {k:(e["observed_mono_ns"]-origin)/1e6 for k,e in selected.items() if e}
        detail["client_event_session_mono_ns"] = {k:e["mono_ns"] for k,e in selected.items() if e and "mono_ns" in e}
        intervals={}
        for label,a,b in (("prepare_start_to_ready_ms","prepare_start","prepare_ready"),
                          ("commit_to_attach_ms","commit","attach"),
                          ("attach_to_first_progress_ms","attach","first_progress")):
            if selected.get(a) and selected.get(b):
                intervals[label]=(selected[b]["observed_mono_ns"]-selected[a]["observed_mono_ns"])/1e6
        detail["stage_intervals_not_additive"]=intervals
        before_attaches = [e for e in attaches if e["observed_mono_ns"] < origin]
        detail["carrier_at_fault"] = before_attaches[-1].get("carrier") if before_attaches else None
        detail["h3_active_when_udp_fault_installed"] = detail["carrier_at_fault"] == "h3"
        detail["pre_fault_switches"] = max(0,len(before_attaches)-1)
        for stage in ("suspected","commit"):
            if selected.get(stage):
                detail["policy_at_"+stage]={k:selected[stage][k] for k in ("threshold_ns","probe_age_ns","samples","demand","reason") if k in selected[stage]}
        if trial.get("variant") in ("causal","probe-only","joint","count") and before_attaches:
            generation=before_attaches[-1].get("generation")
            rtts=[e["rtt_ns"] for e in proxy_client if e.get("event")=="probe_reply" and e.get("generation")==generation
                  and e["observed_mono_ns"]<origin and "rtt_ns" in e][-32:]
            ordered=sorted(rtts)
            if len(ordered)>=3:
                p50=ordered[(len(ordered)-1)//2]
                p90=ordered[(9*len(ordered)-1)//10]
                threshold=max(150_000_000,p90+max(25_000_000,4*(p90-p50)))
                detail["count_threshold_reconstructed_before_fault"]=dict(samples=len(ordered), p50_ns=p50,
                            p90_ns=p90,threshold_ns=threshold,
                            scope="Recomputed from last32 same-generation matched-PONG logs received before install began; log delivery bounds observation.")
        if clock_ok:
            for kind in ("http", "echo", "sse_token"):
                good = [e for e in events if e["kind"] == kind and e.get("status") == "success"]
                attach_wall = selected["attach"]["observed_wall_ns"] if selected["attach"] else fault["wall_ns"]
                after_attach = [e for e in good if epoch+e["recorded_elapsed_ns"] >= attach_wall]
                if after_attach:
                    label="_receipt_after_attach_ms_from_fault" if selected["attach"] else "_receipt_after_fault_without_attach_ms"
                    detail["first_"+kind+label] = (epoch+after_attach[0]["recorded_elapsed_ns"]-fault["wall_ns"])/1e6
                gaps = [(b["recorded_elapsed_ns"]-a["recorded_elapsed_ns"])/1e6 for a,b in zip(good,good[1:])
                        if epoch+b["recorded_elapsed_ns"] >= fault["wall_ns"] and epoch+a["recorded_elapsed_ns"] <= attach_wall+1e9]
                detail[kind+"_largest_receipt_gap_near_recovery_ms"] = max(gaps) if gaps else None
                if kind == "http":
                    new = [e for e in good if e.get("started_ns",0) >= fault["wall_ns"]]
                    if new:
                        detail["first_new_http_completion_ms_from_fault"] = (epoch+new[0]["recorded_elapsed_ns"]-fault["wall_ns"])/1e6
        bracket=trial.get("benchmark_epoch_mono_bounds")
        if bracket and 0 <= bracket["width_ns"] < 20e6:
            detail["benchmark_epoch_mono_bounds"]=bracket
            lower,upper=bracket["lower_ns"],bracket["upper_ns"]
            attach=selected["attach"]["observed_mono_ns"] if selected["attach"] else origin
            for kind in ("http","echo","sse_token"):
                good=[e for e in events if e["kind"]==kind and e.get("status")=="success"]
                unambiguously_after=[e for e in good if lower+e["recorded_elapsed_ns"] >= attach]
                if unambiguously_after:
                    at=unambiguously_after[0]["recorded_elapsed_ns"]
                    label="_receipt_after_attach_ms_from_fault_bounds" if selected["attach"] else "_receipt_after_fault_without_attach_ms_bounds"
                    detail["first_"+kind+label]=[(lower+at-origin)/1e6,(upper+at-origin)/1e6]
                if kind=="http":
                    # The frozen workload starts its fixed-rate scheduler only
                    # after recorder creation. A request cannot begin earlier
                    # than epoch + seq/rps; queue delay only makes it later.
                    rps=summary.get("config",{}).get("http_rps",0)
                    new=[e for e in good if rps>0 and lower+e.get("seq",0)*1e9/rps > origin]
                    if new:
                        at=new[0]["recorded_elapsed_ns"]
                        detail["first_new_http_completion_ms_from_fault_bounds"]=[(lower+at-origin)/1e6,(upper+at-origin)/1e6]
        row["fault_timeline"] = detail
        counters = read(path/"fault-counters.json", {})
        row["blackhole_dropped"] = {side:[part["counter"] for e in data.get("nftables",[]) if "rule" in e
                                                for part in e["rule"].get("expr",[]) if "counter" in part]
                                    for side,data in counters.items()}
    return row


def dist(values):
    a=sorted(v for v in values if v is not None)
    return dict(n=len(a), min=a[0], median=statistics.median(a), max=a[-1]) if a else dict(n=0)


def aggregate(rows):
    groups={}
    for r in rows:
        groups.setdefault((r.get("profile"),r.get("variant")),[]).append(r)
    out=[]
    for (profile,variant), trials in sorted(groups.items()):
        fields=dict(profile=profile,variant=variant,trials=len(trials),
                    completed=sum(r.get("status")=="completed" for r in trials),
                    same_sse_target=sum(r.get("same_sse_target_continuity",False) for r in trials),
                    same_echo_target=sum(r.get("same_echo_target_continuity",False) for r in trials),
                    client_switches=sum(r.get("client_switches",0) for r in trials),
                    preparation_count=sum(r.get("preparation_count",0) for r in trials),
                    delivery_proof_count=sum(r.get("delivery_proof_count",0) for r in trials),
                    canceled_preparations=sum(r.get("canceled_preparations",0) for r in trials))
        fields["h3_active_at_fault_trials"]=sum(r.get("fault_timeline",{}).get("h3_active_when_udp_fault_installed",False) for r in trials)
        fields["pre_fault_switches"]=sum(r.get("fault_timeline",{}).get("pre_fault_switches",0) for r in trials)
        for kind in ("http","echo"):
            ops=[(r.get("operations") or {}).get(kind,{}) for r in trials]
            fields[kind]={k:sum(o.get(k,0) for o in ops) for k in ("total","success","failure","timeout","censored","rejected")}
            fields[kind]["per_trial_p95_ms"]=dist(o.get("successful_latency_ms",{}).get("p95") for o in ops)
        fields["per_trial_sse_max_gap_ms"]=dist((r.get("sse") or {}).get("receive_gap_ms",{}).get("max") for r in trials)
        fields["per_trial_attach_ms_from_fault"]=dist(r.get("fault_timeline",{}).get("client_events_ms_from_fault_install_begin",{}).get("attach") for r in trials)
        fields["per_trial_goodput_mbps"]=dist(r.get("download_goodput_mbps") for r in trials)
        fields["per_trial_qdisc_frame_bytes"]=dist(sum(v["qdisc"]["bytes"] for v in r["link"].values()) for r in trials if r.get("link"))
        out.append(fields)
    return out


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("runs",nargs="+",type=Path)
    ap.add_argument("--out",type=Path)
    args=ap.parse_args()
    rows=[]
    for run in args.runs:
        for path in sorted(run.glob("*/trial.json")):
            try:
                rows.append(one(path.parent))
            except Exception as exc:
                rows.append(dict(trial_id=path.parent.name,profile="analysis_failed",variant="unknown",error=repr(exc)))
    result=dict(trials=rows,groups=aggregate(rows),notes=[
        "Each trial restarts client, server and fixture; requests/tokens within a trial are not independent repetitions.",
        "Input-hook UDP drops are silent; qdisc counters include traffic dropped later at the destination.",
        "First receipt after injection can be an in-flight reply; restoration is reported after client attach, with largest nearby receipt gap.",
        "Fault timestamps bracket firewall commands; proxy log receipt is an upper bound on the internal event.",
        "Matched source connection IDs and client connection counts establish same-target continuity; SSE tail is right-censored.",
        "Qdisc bytes include veth Ethernet MAC headers (14 bytes), not FCS; they include padding, standby, probes and retransmission; startup/warmup separate.",
        "netem rate adds configured 24 bytes per packet for shaping, separately from the measured qdisc byte counter.",
        "Xray is TCP-only and Hysteria here has no TCP standby. Cross-protocol blackhole results are not equal-fallback evidence.",
        "16-second windows and few seeds do not establish long-term false-positive rates or population p99."])
    text=json.dumps(result,indent=2,ensure_ascii=False)+"\n"
    if args.out:
        with args.out.open("x") as f: f.write(text)
    else: print(text,end="")


if __name__=="__main__":
    main()
