#!/usr/bin/env python3
"""Validate a disposable link, preserving raw counters. Not a proxy benchmark."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", required=True)
    ap.add_argument("--netlab", default="/tmp/netlab.py")
    a = ap.parse_args()
    out = Path(a.output)
    out.mkdir(parents=True, exist_ok=False)
    lab = ["python3", a.netlab]

    def cmd(argv, check=True):
        result = subprocess.run(argv, capture_output=True, text=True, check=check, timeout=45)
        return result.stdout

    def snapshot(name):
        data = json.loads(cmd(lab + ["state"]))
        (out / f"{name}.json").write_text(json.dumps(data, indent=2) + "\n")
        return data

    def counter_delta(before, after):
        result = {}
        for ns in ("px-client", "px-server"):
            b = next(x for x in before["namespaces"][ns]["qdisc"] if x["kind"] == "netem")
            e = next(x for x in after["namespaces"][ns]["qdisc"] if x["kind"] == "netem")
            counters = {k: e[k] - b[k] for k in ("bytes", "packets", "drops")}
            def nstat(snapshot):
                for line in snapshot["namespaces"][ns]["nstat_text"].splitlines():
                    fields = line.split()
                    if len(fields) >= 2 and fields[0] == "TcpRetransSegs":
                        return int(fields[1])
                return 0
            counters["tcp_retrans_segments_including_warmup"] = nstat(after) - nstat(before)
            result[ns] = counters
        return result

    # Caller must explicitly schedule this check between workloads.
    profile = cmd(lab + ["profile", "--up", "2", "--down", "8", "--rtt", "60", "--loss", "0", "--seed", "42"])
    (out / "profile.json").write_text(profile)
    cmd(lab + ["unblock-udp"])
    cmd(lab + ["client", "ping", "-n", "-c", "3", "-i", "0.1", "10.203.0.2"])
    ping = cmd(lab + ["client", "ping", "-n", "-c", "20", "-i", "0.1", "10.203.0.2"])
    (out / "ping.txt").write_text(ping)
    snapshot("before")
    server = subprocess.Popen(lab + ["server", "iperf3", "-s", "-B", "10.203.0.2", "-p", "15201"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    udp_code = "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('10.203.0.2',15202));\nwhile True:\n d,p=s.recvfrom(4096); s.sendto(d,p)"
    udp_server = subprocess.Popen(lab + ["server", "python3", "-u", "-c", udp_code], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    udp_client = "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(0.5); s.sendto(b'PROTO-X lab probe',('10.203.0.2',15202)); assert s.recv(4096)==b'PROTO-X lab probe'; print('ok')"
    summary = {"utc": dt.datetime.now(dt.timezone.utc).isoformat(), "purpose": "link-validation-only", "throughput": {}}
    try:
        time.sleep(0.2)
        if server.poll() is not None or udp_server.poll() is not None:
            raise RuntimeError("reserved validation ports busy or server startup failed")
        rtt_code = """import socket,time,json,statistics
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(1)
samples=[]
for i in range(33):
 data=('probe-%03d'%i).encode()
 start=time.monotonic_ns()
 s.sendto(data,('10.203.0.2',15202))
 assert s.recv(4096)==data
 elapsed=(time.monotonic_ns()-start)/1e6
 if i>=3: samples.append(elapsed)
 time.sleep(0.03)
print(json.dumps({'clock':'time.monotonic_ns','warmup':3,'samples_ms':samples,'min_ms':min(samples),'median_ms':statistics.median(samples),'max_ms':max(samples)}))
"""
        rtt = cmd(lab + ["client", "python3", "-c", rtt_code])
        (out / "udp-rtt-monotonic.json").write_text(rtt)
        summary["monotonic_udp_rtt"] = {k: v for k, v in json.loads(rtt).items() if k != "samples_ms"}
        for direction, flags in (("up", []), ("down", ["-R"])):
            before = snapshot(f"{direction}-before")
            raw = cmd(lab + ["client", "iperf3", "-c", "10.203.0.2", "-p", "15201", "-t", "6", "-O", "1", "-J"] + flags)
            (out / f"{direction}.json").write_text(raw)
            data = json.loads(raw)
            if "error" in data:
                raise RuntimeError(data["error"])
            summary["throughput"][direction] = {
                "receiver_mbps": data["end"]["sum_received"]["bits_per_second"] / 1e6,
                "tcp_retransmits": data["end"]["sum_sent"].get("retransmits"),
                "duration_seconds": data["end"]["sum_received"]["seconds"],
            }
            after = snapshot(f"{direction}-after")
            summary["throughput"][direction]["link_counter_delta"] = counter_delta(before, after)
        udp_ok = cmd(lab + ["client", "python3", "-c", udp_client]).strip() == "ok"
        cmd(lab + ["block-udp"])
        blocked = subprocess.run(lab + ["client", "python3", "-c", udp_client], text=True, capture_output=True, timeout=3)
        (out / "udp-blocked.txt").write_text(blocked.stdout + blocked.stderr)
        blocked_ping = cmd(lab + ["client", "ping", "-n", "-c", "3", "-i", "0.1", "10.203.0.2"])
        (out / "ping-during-udp-block.txt").write_text(blocked_ping)
        cmd(lab + ["unblock-udp"])
        restored = cmd(lab + ["client", "python3", "-c", udp_client]).strip() == "ok"
        summary["udp_fault"] = {"before_ok": udp_ok, "blocked_failed": blocked.returncode != 0, "after_ok": restored}
        if not (udp_ok and blocked.returncode != 0 and restored):
            raise RuntimeError("UDP fault validation did not behave as expected")
        summary["ping_summary"] = ping.splitlines()[-2:]
        summary["ping_caveat"] = "iputils ping is a diagnostic only; guest realtime clock adjustments can produce invalid zero values. Use monotonic UDP samples."
        summary["checks_completed"] = True
    finally:
        cmd(lab + ["unblock-udp"])
        for proc in (server, udp_server):
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        snapshot("after")
        (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
