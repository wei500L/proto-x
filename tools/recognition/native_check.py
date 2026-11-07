#!/usr/bin/env python3
"""Run native H2/H3 proxy traffic with ECH off/on on owned local fixtures.

Creates an independent server, CA, inner/outer names and token in .local. The
existing server and its configs are read only. Captures contain only native
client traffic; active TLS state diagnostics use a separate direct connection.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

from local_smoke import HERE, ROOT, private_json, stop, wait_ready


def resolved_config(path):
    value = json.loads(path.read_text())
    for key in ("cert_file", "key_file", "token_file", "cover_dir", "ca_file", "ech_keys_file", "ech_config_file"):
        if value.get(key):
            p = Path(value[key])
            value[key] = str(p if p.is_absolute() else path.parent / p)
    return value


def unused_address(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return "%s:%d" % s.getsockname()


def split(value):
    host, port = value.rsplit(":", 1)
    return host, int(port)


def read_exact(conn, size):
    value = b""
    while len(value) < size:
        more = conn.recv(size - len(value))
        if not more:
            raise EOFError("incomplete local SOCKS exchange")
        value += more
    return value


def socks_connection(socks_address, target):
    conn = socket.create_connection(split(socks_address), timeout=5)
    try:
        conn.sendall(b"\x05\x01\x00")
        if read_exact(conn, 2) != b"\x05\x00":
            raise ValueError("local SOCKS authentication selection failed")
        conn.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(target[0]) + struct.pack("!H", target[1]))
        reply = read_exact(conn, 4)
        if reply[:3] != b"\x05\x00\x00":
            raise ValueError("local SOCKS target connection was rejected")
        size = {1: 4, 4: 16}.get(reply[3])
        if reply[3] == 3:
            size = read_exact(conn, 1)[0]
        if size is None:
            raise ValueError("invalid local SOCKS address type")
        read_exact(conn, size + 2)
        return conn
    except Exception:
        conn.close()
        raise


def request(socks_address, target, path, expected, stream=False):
    start = time.monotonic_ns()
    row = {"workload": "paced_event_stream" if stream else "fixed_response", "request_started_monotonic_ns": start}
    received = b""
    try:
        with socks_connection(socks_address, target) as conn:
            conn.sendall(("GET " + path + " HTTP/1.1\r\nHost: local-workload\r\nConnection: close\r\n\r\n").encode())
            response = http.client.HTTPResponse(conn)
            response.begin()
            row["http_status"] = response.status
            row["headers_elapsed_ms"] = (time.monotonic_ns() - start) / 1e6
            if stream:
                arrivals = []
                while True:
                    line = response.readline(8192)
                    if not line:
                        break
                    received += line
                    if line.startswith(b"data:"):
                        arrivals.append((time.monotonic_ns() - start) / 1e6)
                row["event_arrival_elapsed_ms"] = arrivals
                row["event_count"] = len(arrivals)
            else:
                received = response.read(len(expected) + 1)
            response.close()
        row["status"] = "success" if row["http_status"] == 200 and received == expected else "content_mismatch"
    except Exception as exc:
        row.update(status="request_failed", error={"type": type(exc).__name__, "timeout": isinstance(exc, TimeoutError), "message_redacted": True})
    row["elapsed_ms"] = (time.monotonic_ns() - start) / 1e6
    row["body_bytes"] = len(received)
    row["body_sha256"] = hashlib.sha256(received).hexdigest()
    row["expected_body_sha256"] = hashlib.sha256(expected).hexdigest()
    return row


def run(binary, measurement, server_config, client_config, private, output):
    private.mkdir(mode=0o700, parents=True, exist_ok=False)
    output.mkdir(parents=True, exist_ok=False)
    for src, name in ((binary, "protox"), (measurement, "recognition")):
        shutil.copy2(src, private / name)
    binary, measurement = private / "protox", private / "recognition"
    processes, logs, commands = [], [], []
    target_server = None
    def start(command, label):
        log = (private / (label + ".log")).open("x")
        os.chmod(log.name, 0o600)
        logs.append(log)
        commands.append(command)
        process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        processes.append(process)
        return process
    def command(args, label):
        process = start(args, label)
        if process.wait(timeout=20) != 0:
            raise RuntimeError("native fixture command failed; private logs retained")
    try:
        command([str(measurement), "cert", "-out", str(private / "cert")], "cert")
        identity = json.loads((private / "cert/identity.json").read_text())
        command([str(binary), "ech-keygen", "-dir", str(private / "ech"), "-public-name", identity["ech_public_name"]], "ech-keygen")
        token = private / "token"
        token.write_text(secrets.token_hex(32))
        os.chmod(token, 0o600)
        cfg = resolved_config(server_config)
        cfg.update(web_listen=unused_address(), http3_listen=unused_address(socket.SOCK_DGRAM),
                   cert_file=identity["cert_file"], key_file=identity["key_file"], token_file=str(token),
                   ech_keys_file=str(private / "ech/ech-keys.json"), allow_private_targets=True, max_sessions=8)
        cfg.pop("tls_listen", None)
        cfg.pop("quic_listen", None)
        own_server = private / "server.json"
        private_json(own_server, cfg)
        server_process = start([str(binary), "server", "-config", str(own_server)], "server")
        until = time.monotonic() + 10
        while True:
            text = (private / "server.log").read_text()
            if "HTTPS listener ready" in text and "HTTP/3 listener ready" in text:
                break
            if server_process.poll() is not None or time.monotonic() >= until:
                raise RuntimeError("owned native server did not become ready")
            time.sleep(0.03)

        fixed = secrets.token_bytes(32768)
        events = [("data: %d %s\n\n" % (i, "controlled-event" * 3)).encode() for i in range(16)]
        stream_body = b"".join(events)
        origin_rows, lock = [], threading.Lock()
        class Origin(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, *_args):
                pass
            def do_GET(self):
                streaming = self.path == "/stream"
                body = stream_body if streaming else fixed
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Type", "text/event-stream" if streaming else "application/octet-stream")
                self.send_header("Connection", "close")
                self.end_headers()
                record = {"workload": "paced_event_stream" if streaming else "fixed_response", "generated_monotonic_ns": []}
                try:
                    if streaming:
                        for data in events:
                            record["generated_monotonic_ns"].append(time.monotonic_ns())
                            self.wfile.write(data)
                            self.wfile.flush()
                            time.sleep(0.02)
                    else:
                        self.wfile.write(body)
                        self.wfile.flush()
                    record["status"] = "produced"
                except Exception as exc:
                    record.update(status="write_failed", error_type=type(exc).__name__)
                with lock:
                    origin_rows.append(record)
        target_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        target_server.daemon_threads = True
        threading.Thread(target=lambda: target_server.serve_forever(poll_interval=0.05), daemon=True).start()
        names = private / "names.json"
        private_json(names, {"inner_names": [identity["server_name"]], "outer_names": [identity["ech_public_name"]]})
        scenarios = []
        for network in ("h2", "h3"):
            for ech in (False, True):
                label = "native-" + network + ("-ech-on" if ech else "-ech-off")
                capture_dir = private / ("capture-" + label)
                target = cfg["web_listen" if network == "h2" else "http3_listen"]
                relay = start([sys.executable, str(HERE / "relay.py"), "--out", str(capture_dir), "--label", label,
                               "--capture-bytes", "1048576", "--capture-packets", "512",
                               "--tcp-target" if network == "h2" else "--udp-target", target], "relay-" + label)
                ready = wait_ready(capture_dir / "ready.json", relay)
                routed = ready["tcp_listen" if network == "h2" else "udp_listen"]
                client = resolved_config(client_config)
                client.update(endpoints=[{"network": network, "address": "%s:%d" % tuple(routed), "server_name": identity["server_name"]}],
                              socks_listen=unused_address(), token_file=str(token), ca_file=identity["ca_file"],
                              pin_sha256=identity["pin_sha256"], experimental_pin_only=False)
                if ech:
                    client["ech_config_file"] = str(private / "ech/ech-config.bin")
                else:
                    client.pop("ech_config_file", None)
                client_path = private / (label + ".json")
                private_json(client_path, client)
                client_process = start([str(binary), "client", "-config", str(client_path)], "client-" + label)
                until = time.monotonic() + 10
                while True:
                    text = (private / ("client-" + label + ".log")).read_text()
                    if "SOCKS5 listener ready" in text:
                        break
                    if client_process.poll() is not None or time.monotonic() >= until:
                        raise RuntimeError("owned native client did not become ready")
                    time.sleep(0.03)
                diagnostics = {"label": label + "-tlscheck", "network": network, "address": target,
                               "server_name": identity["server_name"], "ca_file": identity["ca_file"],
                               "pin_sha256": identity["pin_sha256"], "timeout_ms": 3000}
                if ech:
                    diagnostics["ech_config_file"] = client["ech_config_file"]
                diagnostic_path = private / (label + "-tlscheck.json")
                private_json(diagnostic_path, diagnostics)
                diagnostic_report = output / (label + "-tlscheck.json")
                command([str(measurement), "tlscheck", "-config", str(diagnostic_path), "-out", str(diagnostic_report)], label + "-tlscheck")
                before = len(origin_rows)
                requests = [request(client["socks_listen"], target_server.server_address, "/fixed", fixed) for _ in range(3)]
                requests.append(request(client["socks_listen"], target_server.server_address, "/stream", stream_body, True))
                # The stream handler sleeps once after its last write; allow
                # its observed source event log to be committed before scope ends.
                time.sleep(0.04)
                with lock:
                    origins = list(origin_rows[before:])
                stop(client_process)
                stop(relay)
                hello_path = output / (label + "-clienthello.json")
                command([sys.executable, str(HERE / "analyze.py"), "--capture", str(capture_dir / "capture.jsonl"),
                         "--label", label, "--names-private", str(names), "--out", str(hello_path)], label + "-analyze")
                tls = json.loads(diagnostic_report.read_text())
                hello = json.loads(hello_path.read_text())
                expected_class = "configured_outer_name" if ech else "configured_inner_name"
                decoded = [x for x in hello["observations"] if x["status"] == "client_hello_decoded"]
                checks = {
                    "four_proxy_requests_succeeded": len(requests) == 4 and all(x["status"] == "success" for x in requests),
                    "origin_observed_four_requests": len(origins) == 4 and all(x["status"] == "produced" for x in origins),
                    "sixteen_stream_events_received": requests[-1].get("event_count") == 16,
                    "tls_state_completed_and_ca_verified": tls.get("status") == "handshake_completed" and tls.get("certificate_chain_verified") is True,
                    "actual_tls_ech_acceptance_matches_setting": tls.get("ech_accepted") is ech,
                    "tls_negotiated_requested_alpn": tls.get("negotiated_alpn") == network,
                    "all_observed_clienthellos_decoded": bool(decoded) and len(decoded) == len(hello["observations"]),
                    "no_legacy_custom_alpn": all(not x["client_hello"]["legacy_custom_alpn_observed"] for x in decoded),
                    "visible_name_class_matches_ech_setting": all(x["client_hello"]["sni"]["names"] and all(n["class"] == expected_class for n in x["client_hello"]["sni"]["names"]) for x in decoded),
                    "native_ech_extension_matches_setting": all(x["client_hello"]["ech_extension_present"] is ech for x in decoded),
                    "capture_clean_and_no_inspection_errors": hello["capture_shutdown_observed"] and not hello["inspection_errors"],
                    "capture_not_truncated": all(not x["capture_truncated"] for x in hello["relay_counts"]),
                }
                row = {"label": label, "network": network, "ech_configured": ech, "checks": checks,
                       "status": "passed" if all(checks.values()) else "failed", "requests": requests, "origin_observations": origins,
                       "decoded_native_clienthellos": len(decoded), "tls_state_diagnostic_is_a_separate_direct_connection": True}
                (output / (label + "-workload.json")).write_text(json.dumps(row, indent=2) + "\n")
                scenarios.append(row)
        summary = {"schema": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
                   "status": "passed" if all(x["status"] == "passed" for x in scenarios) else "failed", "scenarios": scenarios,
                   "candidate_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                   "measurement_binary_sha256": hashlib.sha256(measurement.read_bytes()).hexdigest(),
                   "scope": "real native client/server over owned loopback H2/H3, ECH off/on, controlled HTTP/SSE target through SOCKS5",
                   "trust_policy": "generated local CA plus expected inner name and additional pin; no pin-only mode, no public-CA claim",
                   "fixture_server_session_limit": 8,
                   "ech_evidence": "native outer ClientHello bytes and successful proxy requests; separate direct TLS state explicitly reports ECHAccepted",
                   "limitations": ["This is a functional local experiment, not a loss/latency comparison, a long soak, a cover classifier, or Russian reachability evidence.",
                                   "The native client's configured ECH is fail-closed in WebClientTLS. The TLS state diagnostic is a separate connection, not an instrumented native-client callback.",
                                   "Off/on captures use different configured handshake behavior; the ECH extension itself remains observable."]}
        (output / "native-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        private_json(private / "commands.json", {"commands": commands, "private": True})
        return summary
    finally:
        for process in reversed(processes):
            stop(process)
        if target_server:
            target_server.shutdown()
            target_server.server_close()
        for log in logs:
            log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--measurement-binary", required=True, type=Path)
    parser.add_argument("--server-config", required=True, type=Path)
    parser.add_argument("--client-config", required=True, type=Path)
    parser.add_argument("--private", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    if not args.private.resolve().is_relative_to((ROOT / ".local").resolve()):
        parser.error("private outputs must stay below this repository's ignored .local directory")
    result = run(args.binary.resolve(), args.measurement_binary.resolve(), args.server_config.resolve(), args.client_config.resolve(),
                 args.private.resolve(), args.out.resolve())
    print(json.dumps({"status": result["status"], "out": str(args.out),
                      "scenarios": [{"label": x["label"], "status": x["status"], "failed_checks": [k for k, v in x["checks"].items() if not v]} for x in result["scenarios"]]}))
    if result["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
