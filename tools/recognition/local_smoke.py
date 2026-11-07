#!/usr/bin/env python3
"""Run real loopback H2/H3 fixture probes and inspect their observed bytes.

The fixture is an ordinary same-stack website, not a proxy. This verifies the
measurement tools before a candidate comparison; it cannot show anonymity.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import time


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def private_json(path, value):
    with path.open("x") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2)
        stream.write("\n")


def wait_ready(path, process, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if path.exists():
            try:
                return json.loads(path.read_text())
            except json.JSONDecodeError:
                pass
        if process.poll() is not None:
            raise RuntimeError("private fixture process exited before readiness")
        time.sleep(0.03)
    raise RuntimeError("private fixture readiness deadline")


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def execute(binary, private, output, repeats):
    private.mkdir(mode=0o700, parents=True, exist_ok=False)
    output.mkdir(parents=True, exist_ok=False)
    shutil.copy2(binary, private / "recognition")
    binary = private / "recognition"
    processes, logfiles = [], []
    commands = []
    def start(command, label):
        commands.append(command)
        log = (private / (label + ".log")).open("x")
        os.chmod(log.name, 0o600)
        logfiles.append(log)
        process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        processes.append(process)
        return process
    def run(command, label, timeout=45):
        process = start(command, label)
        if process.wait(timeout=timeout) != 0:
            raise RuntimeError("private command failed: " + label)
    try:
        run([str(binary), "cert", "-out", str(private / "cert")], "cert")
        identity = json.loads((private / "cert/identity.json").read_text())
        site = private / "site"
        site.mkdir(mode=0o700)
        (site / "index.html").write_text("<!doctype html><html><title>Notes</title><h1>Notes</h1><p>A quiet place for notes.</p></html>\n")
        stamp = 1700000000
        os.utime(site / "index.html", (stamp, stamp))
        ordinary_config = private / "ordinary.json"
        private_json(ordinary_config, {"label": "ordinary", "tcp_listen": "127.0.0.1:0", "udp_listen": "127.0.0.1:0",
                                      "cert_file": identity["cert_file"], "key_file": identity["key_file"],
                                      "site_root": str(site), "ready_file": str(private / "ordinary-ready.json")})
        fixture = start([str(binary), "ordinary", "-config", str(ordinary_config)], "ordinary")
        ordinary = wait_ready(private / "ordinary-ready.json", fixture)
        capture_dir = private / "capture-ordinary-active"
        relay = start([sys.executable, str(HERE / "relay.py"), "--out", str(capture_dir), "--label", "ordinary-active",
                       "--tcp-target", ordinary["tcp_listen"], "--udp-target", ordinary["udp_listen"]], "relay")
        relay_ready = wait_ready(capture_dir / "ready.json", relay)
        reports, probes = {}, []
        for network, listen in (("h2", "tcp_listen"), ("h3", "udp_listen")):
            address = relay_ready[listen]
            c = {"label": "ordinary-active-" + network, "network": network,
                 "address": "%s:%d" % (address[0], address[1]), "server_name": identity["server_name"],
                 "ca_file": identity["ca_file"], "pin_sha256": identity["pin_sha256"],
                 "repeats": repeats, "timeout_ms": 1500}
            config_file = private / ("probe-" + network + ".json")
            private_json(config_file, c)
            report_file = output / ("ordinary-" + network + ".json")
            reports[network] = report_file
            probes.append(start([str(binary), "probe", "-config", str(config_file), "-out", str(report_file)], "probe-" + network))
        for probe in probes:
            if probe.wait(timeout=45) != 0:
                raise RuntimeError("active fixture probe failed; inspect private logs")
        stop(relay)
        names = private / "names.json"
        private_json(names, {"cover_names": [identity["server_name"]], "legacy_names": []})
        run([sys.executable, str(HERE / "analyze.py"), "--capture", str(capture_dir / "capture.jsonl"),
             "--label", "ordinary-active", "--names-private", str(names),
             "--out", str(output / "clienthello.json")], "analyze")
        checks = []
        observations = {}
        expected = {"root_get": 200, "root_head": 200, "protocol_get": 404, "protocol_head": 404,
                    "protocol_post_no_auth": 405, "protocol_post_wrong_auth": 405, "protocol_post_malformed_auth": 405,
                    "protocol_wrong_method_put": 405, "unknown_get": 404, "unknown_post": 405, "root_options": 405}
        for network, report_file in reports.items():
            rows = json.loads(report_file.read_text())["observations"]
            observations[network] = rows
            checks.append({"check": network + "_attempt_denominator", "ok": len(rows) == repeats * 13,
                           "observed": len(rows), "expected": repeats * 13})
            for row in rows:
                if row["case"] in expected:
                    ok = (row.get("status") == "response_observed" and row.get("http_status") == expected[row["case"]]
                          and row.get("negotiated_alpn") == network and row.get("certificate_chain_verified") is True
                          and not row.get("body_truncated_at_bound"))
                    checks.append({"check": network + "_ordinary_http", "case": row["case"], "repeat": row["repeat"], "ok": ok})
        hello = json.loads((output / "clienthello.json").read_text())
        checks.append({"check": "clean_capture_shutdown", "ok": hello["capture_shutdown_observed"]})
        checks.append({"check": "no_initial_inspection_errors", "ok": not hello["inspection_errors"]})
        checks.append({"check": "clienthello_denominator", "ok": hello["decoded_client_hello_count"] == 26 * repeats,
                       "observed": hello["decoded_client_hello_count"], "expected": 26 * repeats})
        checks.append({"check": "no_captured_prefix_truncation",
                       "ok": all(not x["capture_truncated"] for x in hello["relay_counts"])})
        matches = sum(x.get("client_hello", {}).get("legacy_custom_alpn_observed", False) for x in hello["observations"])
        checks.append({"check": "intentional_legacy_offer_count", "ok": matches == 2 * repeats,
                       "observed": matches, "expected": 2 * repeats})
        mappings = []
        reflected = 0
        prior_server_payloads = {}
        for line in (capture_dir / "capture.jsonl").open():
            event = json.loads(line)
            if event.get("kind") == "private_udp_mapping":
                mappings.append(event)
            if event.get("kind") == "udp_datagram":
                seen = prior_server_payloads.setdefault(event["flow"], set())
                if event["direction"] == "server_to_client":
                    seen.add(event["data_base64"])
                elif event["data_base64"] in seen:
                    reflected += 1
        backend_ports = [x["backend_local"][1] for x in mappings]
        checks.append({"check": "distinct_udp_backend_ports", "ok": len(backend_ports) == len(set(backend_ports)),
                       "mapping_count": len(mappings)})
        checks.append({"check": "no_byte_identical_server_udp_reflection", "ok": reflected == 0, "observed": reflected})
        result = {"schema": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
                  "status": "passed" if all(x["ok"] for x in checks) else "failed", "checks": checks,
                  "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "repeats": repeats,
                  "scope": "real local ordinary HTTP fixture and controlled relay; not a candidate protocol comparison",
                  "certificate_policy": "generated private CA and name validation plus additional pin; no system trust change",
                  "candidate_authenticated_traffic_tested": False,
                  "native_client_traffic_capture": False,
                  "timing_interpretation": "loopback observations only; no link impairment or Russian-network claim"}
        (output / "smoke.json").write_text(json.dumps(result, indent=2) + "\n")
        private_json(private / "commands.json", {"commands": commands, "private": True})
        sources = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                   for path in sorted(HERE.rglob("*")) if path.is_file() and path.suffix in (".py", ".go", ".hex")}
        (output / "source-manifest.json").write_text(json.dumps({"snapshot_at_run_end": True, "files": sources}, indent=2) + "\n")
        return result
    finally:
        for process in reversed(processes):
            stop(process)
        for log in logfiles:
            log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--private", type=Path, required=True, help="new directory below ignored .local")
    parser.add_argument("--out", type=Path, required=True, help="new redacted result directory")
    parser.add_argument("--repeats", type=int, default=2, choices=range(1, 5))
    args = parser.parse_args()
    if not args.private.resolve().is_relative_to((ROOT / ".local").resolve()):
        parser.error("private outputs must remain below this repository's ignored .local directory")
    result = execute(args.binary.resolve(), args.private.resolve(), args.out.resolve(), args.repeats)
    print(json.dumps({"status": result["status"], "checks": len(result["checks"]), "out": str(args.out)}))
    if result["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
