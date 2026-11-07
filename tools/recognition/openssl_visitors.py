#!/usr/bin/env python3
"""Use an independent installed OpenSSL TLS client for ordinary HTTP visitors.

Raw OpenSSL output includes peer identity and is saved only beside the private
config. This tool exports selected response fields and verification outcomes.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time


SAFE_HEADERS = {"content-type", "content-length", "allow", "accept-ranges", "cache-control",
                "content-encoding", "x-content-type-options", "vary", "last-modified"}


class MemorySocket:
    def __init__(self, data):
        self.data = data

    def makefile(self, *_args, **_kwargs):
        return io.BytesIO(self.data)


def run_probe(config, config_path, output, executable):
    if output.exists():
        raise ValueError("refusing to overwrite an existing OpenSSL report")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", config["label"]):
        raise ValueError("label must be a redacted category")
    private = config_path.with_name(config_path.stem + "-openssl-private")
    private.mkdir(mode=0o700, exist_ok=False)
    version = subprocess.run([executable, "version"], capture_output=True, timeout=3, check=True).stdout.decode().strip()
    try:
        ipaddress.ip_address(config["server_name"])
        verify_flag = "-verify_ip"
    except ValueError:
        verify_flag = "-verify_hostname"
    repeats = int(config.get("repeats", 1))
    if not 1 <= repeats <= 20:
        raise ValueError("OpenSSL repeat bound exceeded")
    rows = []
    for repeat in range(repeats):
        for offer in (False, True):
            for method in ("GET", "HEAD"):
                profile = "http11_explicit_alpn" if offer else "https_no_alpn"
                name = "openssl_" + profile + "_root_" + method.lower()
                row = {"case": name, "repeat": repeat, "method": method, "visitor_profile": profile,
                       "authentication_class": "absent", "offered_alpn": ["http/1.1"] if offer else [],
                       "tls_client_stack": "installed OpenSSL s_client"}
                command = [executable, "s_client", "-connect", config["address"], "-servername", config["server_name"],
                           "-verify_return_error", verify_flag, config["server_name"],
                           "-tls1_3", "-brief", "-ign_eof", "-nocommands"]
                if config.get("ca_file"):
                    command.extend(["-CAfile", config["ca_file"]])
                if offer:
                    command.extend(["-alpn", "http/1.1"])
                request = (method + " / HTTP/1.1\r\nHost: " + config["server_name"] + "\r\nConnection: close\r\n\r\n").encode()
                start = time.monotonic()
                stdout, stderr = b"", b""
                try:
                    process = subprocess.run(command, input=request, capture_output=True,
                                             timeout=max(1, config.get("timeout_ms", 2500) / 1000))
                    stdout, stderr = process.stdout, process.stderr
                    row["process_exit_code"] = process.returncode
                    row["complete_elapsed_ms"] = (time.monotonic() - start) * 1000
                    row["certificate_verification_reported"] = b"Verification: OK" in stderr
                    protocol = re.search(rb"Protocol version:\s*(TLSv[0-9.]+)", stderr)
                    if protocol:
                        row["tls_version"] = protocol.group(1).decode()
                    negotiated = re.search(rb"ALPN protocol:\s*([^\s]+)", stderr)
                    if negotiated:
                        row["negotiated_alpn"] = negotiated.group(1).decode("ascii", errors="replace")
                    response = http.client.HTTPResponse(MemorySocket(stdout), method=method)
                    response.begin()
                    row["http_status"] = response.status
                    row["http_protocol"] = "HTTP/1.1" if response.version == 11 else "HTTP/1.0"
                    header = {}
                    for key in set(k.lower() for k in response.headers):
                        if key == "date":
                            continue
                        values = response.headers.get_all(key)
                        header[key] = sorted(values) if key in SAFE_HEADERS else {"value_count": len(values), "values_redacted": True}
                    row["headers"] = header
                    row["content_length"] = int(response.headers["Content-Length"]) if "Content-Length" in response.headers else -1
                    payload = response.read(65537)
                    row["body_bytes_observed"] = len(payload)
                    row["body_truncated_at_bound"] = len(payload) > 65536
                    row["body_sha256"] = hashlib.sha256(payload).hexdigest()
                    row["status"] = "response_observed" if process.returncode == 0 else "response_observed_with_process_error"
                    response.close()
                except subprocess.TimeoutExpired as exc:
                    stdout, stderr = exc.stdout or b"", exc.stderr or b""
                    row.update(status="request_failed", error={"types": [type(exc).__name__], "timeout": True, "message_redacted": True})
                except Exception as exc:
                    row.update(status="request_failed", error={"types": [type(exc).__name__], "timeout": False, "message_redacted": True})
                prefix = private / (str(repeat) + "-" + name)
                for suffix, data in ((".stdout", stdout), (".stderr", stderr)):
                    path = Path(str(prefix) + suffix)
                    path.write_bytes(data)
                    os.chmod(path, 0o600)
                command_path = Path(str(prefix) + ".command.json")
                command_path.write_text(json.dumps(command) + "\n")
                os.chmod(command_path, 0o600)
                rows.append(row)
    report = {"schema": 1, "label": config["label"], "network": "https_openssl_tcp",
              "created_utc": datetime.now(timezone.utc).isoformat(), "observations": rows, "attempted_cases": len(rows),
              "tool": {"openssl_version": version, "openssl_binary_sha256": hashlib.sha256(Path(executable).read_bytes()).hexdigest()},
              "certificate_policy": "OpenSSL chain and expected-name verification with verify_return_error; explicit CA file when configured",
              "pin_policy": "this independent client does not apply the optional Go-probe additional pin",
              "limitations": ["These are installed OpenSSL HTTP/1.1 visitors, not browser or native proxy traffic.",
                              "ALPN offered is also observable at the separate relay; negotiated ALPN is exported only if OpenSSL reports it.",
                              "Private stdout/stderr are retained; public reports contain selected generic headers and body hashes only.",
                              "An OpenSSL/Go comparison is not a diverse detector evaluation or an indistinguishability guarantee."]}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(output), "attempted_cases": len(rows)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    executable = shutil.which("openssl")
    if not executable:
        parser.error("installed OpenSSL executable is required")
    run_probe(json.loads(args.config.read_text()), args.config.resolve(), args.out.resolve(), executable)


if __name__ == "__main__":
    main()
