#!/usr/bin/env python3
"""Compare an already running, owned loopback candidate with its ordinary site.

The private config supplies candidate_tcp/candidate_udp, server_name, ca_file,
pin_sha256, cert_file, key_file and site_root. The latter three are passed to
the ordinary fixture. The candidate is never started, changed or terminated.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from local_smoke import HERE, ROOT, private_json, stop, wait_ready


def loopback(value):
    host, port = value.rsplit(":", 1)
    if not ipaddress.ip_address(host.strip("[]")).is_loopback or not 0 < int(port) < 65536:
        raise ValueError("this harness accepts already running loopback candidates only")


def execute(binary, config_path, private, output):
    c = json.loads(config_path.read_text())
    networks = [n for n, field in (("h2", "candidate_tcp"), ("h3", "candidate_udp")) if c.get(field)]
    if not networks:
        raise ValueError("private config requires at least one candidate address")
    for field in ("candidate_tcp", "candidate_udp"):
        if c.get(field):
            loopback(c[field])
    repeats = int(c.get("repeats", 3))
    if not 1 <= repeats <= 4:
        raise ValueError("bounded comparison accepts 1..4 repeats")
    profile = c.get("reference_profile", "candidate_options")
    if profile not in ("candidate_options", "stock_go"):
        raise ValueError("reference_profile must be candidate_options or stock_go")
    openssl = bool(c.get("openssl_visitors", True))
    private.mkdir(mode=0o700, parents=True, exist_ok=False)
    output.mkdir(parents=True, exist_ok=False)
    shutil.copy2(binary, private / "recognition")
    binary = private / "recognition"
    private_json(private / "input.json", c)
    processes, logs, commands = [], [], []
    def start(command, label):
        log = (private / (label + ".log")).open("x")
        os.chmod(log.name, 0o600)
        logs.append(log)
        commands.append(command)
        p = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        processes.append(p)
        return p
    def run(command, label):
        p = start(command, label)
        if p.wait(timeout=45) != 0:
            raise RuntimeError("comparison command failed; inspect its private log")
    try:
        ordinary_config = private / "ordinary.json"
        private_json(ordinary_config, {"label": "ordinary", "tcp_listen": "127.0.0.1:0", "udp_listen": "127.0.0.1:0",
                                      "cert_file": c["cert_file"], "key_file": c["key_file"], "site_root": c["site_root"],
                                      "tls_profile": profile,
                                      "ready_file": str(private / "ordinary-ready.json")})
        ordinary_process = start([str(binary), "ordinary", "-config", str(ordinary_config)], "ordinary")
        ordinary = wait_ready(private / "ordinary-ready.json", ordinary_process)
        relays, relay_readiness = [], {}
        for label, addresses in (("candidate", {"h2": c.get("candidate_tcp"), "h3": c.get("candidate_udp")}),
                                 ("ordinary", {"h2": ordinary["tcp_listen"], "h3": ordinary["udp_listen"]})):
            capture_dir = private / ("capture-" + label + "-active")
            command = [sys.executable, str(HERE / "relay.py"), "--out", str(capture_dir), "--label", label + "-active"]
            for network, flag in (("h2", "--tcp-target"), ("h3", "--udp-target")):
                if network in networks:
                    command.extend([flag, addresses[network]])
            relay = start(command, "relay-" + label)
            relays.append(relay)
            relay_readiness[label] = wait_ready(capture_dir / "ready.json", relay)
        probe_processes = []
        for network in networks:
            for label in ("candidate", "ordinary"):
                address = relay_readiness[label]["tcp_listen" if network == "h2" else "udp_listen"]
                probe_config = {"label": label + "-active-" + network, "network": network,
                                "address": "%s:%d" % (address[0], address[1]), "server_name": c["server_name"],
                                "ca_file": c.get("ca_file", ""), "pin_sha256": c.get("pin_sha256", ""),
                                "protocol_path": c.get("protocol_path", "/api/sync?carrier=recognition&stream=1"),
                                "timeout_ms": c.get("timeout_ms", 2000), "repeats": repeats}
                path = private / ("probe-" + label + "-" + network + ".json")
                private_json(path, probe_config)
                probe_processes.append(start([str(binary), "probe", "-config", str(path), "-out",
                                              str(output / (label + "-" + network + ".json"))], "probe-" + label + "-" + network))
                if network == "h2":
                    probe_processes.append(start([str(binary), "visitors", "-config", str(path), "-out",
                                                  str(output / (label + "-visitors.json"))], "visitors-" + label))
                    if openssl:
                        probe_processes.append(start([sys.executable, str(HERE / "openssl_visitors.py"), "--config", str(path), "--out",
                                                      str(output / (label + "-openssl.json"))], "openssl-" + label))
        for p in probe_processes:
            if p.wait(timeout=45) != 0:
                raise RuntimeError("active pair probe failed; inspect private logs")
        for relay in relays:
            stop(relay)
        names = private / "names.json"
        private_json(names, {"cover_names": [c["server_name"]], "legacy_names": c.get("legacy_names", [])})
        for label in ("candidate", "ordinary"):
            run([sys.executable, str(HERE / "analyze.py"), "--capture", str(private / ("capture-" + label + "-active/capture.jsonl")),
                 "--label", label + "-active", "--names-private", str(names),
                 "--out", str(output / (label + "-clienthello.json"))], "analyze-" + label)
        comparisons = {}
        extra = (["visitors"] + (["openssl"] if openssl else [])) if "h2" in networks else []
        for network in networks + extra:
            path = output / ("compare-" + network + ".json")
            run([sys.executable, str(HERE / "compare.py"), "--candidate", str(output / ("candidate-" + network + ".json")),
                 "--reference", str(output / ("ordinary-" + network + ".json")), "--out", str(path)], "compare-" + network)
            result = json.loads(path.read_text())
            comparisons[network] = {key: result[key] for key in ("candidate_attempts", "reference_attempts", "pair_status_counts",
                                                                "candidate_status_counts", "reference_status_counts")}
        summary = {"schema": 1, "created_utc": datetime.now(timezone.utc).isoformat(), "repeats": repeats,
                   "scope": "actual loopback candidate versus same-stack ordinary fixture; only declared unauthenticated/legacy probes",
                   "comparisons": comparisons, "positive_authenticated_native_client_tested": False,
                   "candidate_process_management": "external; this harness did not start/change/stop it",
                   "ordinary_control": "same supplied certificate and site tree; direct cover.Site handler",
                   "reference_profile": profile,
                   "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                   "timing_interpretation": "retained observations, not a statistical indistinguishability claim"}
        (output / "pair-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        private_json(private / "commands.json", {"commands": commands, "private": True})
        return summary
    finally:
        for p in reversed(processes):
            stop(p)
        for log in logs:
            log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--private", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    if not args.private.resolve().is_relative_to((ROOT / ".local").resolve()):
        parser.error("private outputs must remain below this repository's ignored .local directory")
    summary = execute(args.binary.resolve(), args.config.resolve(), args.private.resolve(), args.out.resolve())
    print(json.dumps({"out": str(args.out), "comparisons": summary["comparisons"]}))


if __name__ == "__main__":
    main()
