#!/usr/bin/env python3
"""Loopback interoperability checks; not a network performance benchmark."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

import configure


PAYLOAD = bytes(range(256)) * 32


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def log_message(self, fmt, *args):
        pass


def wait_port(port, processes, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(p.poll() is not None for p in processes):
            raise RuntimeError("baseline process exited early; inspect private smoke logs")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("baseline SOCKS listener did not become available")


def run_pair(binary, name, out, socks, configs, count):
    processes, logs = [], []
    results = []
    try:
        for role, config in zip(("server", "client"), configs):
            log = (out / f"{name}-{role}.log").open("w")
            logs.append(log)
            if name == "xray":
                command = [str(binary), "run", "-c", str(config)]
            else:
                command = [str(binary), role, "--disable-update-check", "-c", str(config)]
            processes.append(subprocess.Popen(command, stdout=log, stderr=log))
        wait_port(socks, processes)
        for i in range(count):
            started = time.monotonic()
            r = subprocess.run(["curl", "-fsS", "--max-time", "8", "--noproxy", "",
                "--socks5-hostname", f"127.0.0.1:{socks}", "http://127.0.0.1:39480/bytes"],
                capture_output=True)
            elapsed = time.monotonic() - started
            ok = r.returncode == 0 and r.stdout == PAYLOAD
            results.append({"request": i, "ok": ok, "elapsed_ms": elapsed * 1000,
                "bytes": len(r.stdout), "sha256": hashlib.sha256(r.stdout).hexdigest(),
                "error": r.stderr.decode(errors="replace") if not ok else ""})
    finally:
        for p in reversed(processes):
            p.terminate()
        for p in reversed(processes):
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=3)
        for log in logs:
            log.close()
    return {"baseline": name, "requests": count, "successes": sum(r["ok"] for r in results),
            "events": results}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bin", type=Path, default=Path(".local/baselines/bin/darwin-arm64"))
    p.add_argument("--out", type=Path, default=Path(".local/baselines/smoke"))
    p.add_argument("--count", type=int, default=3)
    p.add_argument("--cover", type=Path, help="compiled tlscover binary; built with Go if omitted")
    args = p.parse_args()
    os.umask(0o077)
    cfg_args = configure.parser().parse_args(["--server", "127.0.0.1", "--listen", "127.0.0.1",
        "--out", str(args.out), "--xray", str(args.bin / "xray"),
        "--xray-port", "39400", "--hysteria-port", "39401",
        "--socks-xray", "39801", "--socks-hysteria", "39802",
        "--reality-sni", "protox-baseline.test", "--reality-target", "127.0.0.1:39443",
        "--allow-test-cidr", "127.0.0.1/32"])
    out = configure.make_configs(cfg_args)
    origin = http.server.ThreadingHTTPServer(("127.0.0.1", 39480), Origin)
    # Apple's system Python can be built against LibreSSL without TLS 1.3.
    # A Go HTTPS server gives the local REALITY target a genuine TLS 1.3 handshake.
    cover_binary = args.cover or (out / "tlscover")
    if args.cover is None:
        subprocess.run(["go", "build", "-o", str(cover_binary),
                        "scripts/baselines/tlscover.go"], check=True)
    cover_log = (out / "cover.log").open("w")
    cover = subprocess.Popen([str(cover_binary), "-listen", "127.0.0.1:39443",
        "-cert", str(out / "tls-cert.pem"), "-key", str(out / "tls-key.pem")],
        stdout=cover_log, stderr=cover_log)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    result = {"kind": "loopback-smoke", "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "payload_bytes": len(PAYLOAD), "results": []}
    try:
        wait_port(39443, [cover])
        result["results"].append(run_pair(args.bin / "xray", "xray", out, 39801,
            [out / "xray-server.json", out / "xray-client.json"], args.count))
        for profile in ("bbr-standard", "bbr-conservative", "brutal"):
            result["results"].append(run_pair(args.bin / "hysteria", "hysteria-" + profile, out, 39802,
                [out / f"hysteria-server-{profile}.json", out / f"hysteria-client-{profile}.json"], args.count))
    finally:
        origin.shutdown()
        origin.server_close()
        cover.terminate()
        cover.wait(timeout=3)
        cover_log.close()
    (out / "smoke-results.json").write_text(json.dumps(result, indent=2) + "\n")
    for r in result["results"]:
        print(f"{r['baseline']}: {r['successes']}/{r['requests']} exact 8192-byte responses through SOCKS5")
    if any(r["successes"] != r["requests"] for r in result["results"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
