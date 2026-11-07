#!/usr/bin/env python3
"""Measure local carrier/padding cost with real SOCKS workloads and zero payload capture.

Only owned loopback processes are started and stopped. Each invocation freezes its
binaries and relay, refuses existing study directories, and retains failed trials.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
CASES = {"h2-p0": ("h2", 0), "h3-p127": ("h3", 127),
         "h2-p127": ("h2", 127), "h3-p0": ("h3", 0),
         "tls": ("tls", 0), "quic": ("quic", 0)}


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    # Metadata updates are atomic; trial data and binary snapshots are never reused.
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def redact(value, private, output):
    if isinstance(value, str):
        return value.replace(str(private), "$PRIVATE").replace(str(output), "$RESULTS").replace(str(ROOT), "$REPO")
    if isinstance(value, list):
        return [redact(x, private, output) for x in value]
    if isinstance(value, dict):
        return {k: redact(v, private, output) for k, v in value.items()}
    return value


def unused_port(transport="tcp"):
    kind = socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM
    while True:
        with socket.socket(socket.AF_INET, kind) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        if port not in (18443, 11888):
            return port


def await_condition(process, predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"owned process {process.pid} exited {process.returncode} before readiness")
        if predicate():
            return
        time.sleep(.04)
    raise TimeoutError(f"owned process {process.pid} did not become ready")


def can_connect(port):
    try:
        with socket.create_connection(("127.0.0.1", port), .1):
            return True
    except OSError:
        return False


class TrialProcesses:
    def __init__(self, directory):
        self.directory = directory
        self.records = {}
        self.commands = []
        self.lock = threading.Lock()
        self.epoch = time.monotonic_ns()
        self.stopping = threading.Event()
        self.sampler = threading.Thread(target=self.sample, daemon=True)
        self.samples = []
        self.sampler.start()

    def start(self, role, command):
        log = (self.directory / (role + ".log")).open("x")
        process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        entry = {"process": process, "log": log, "pid": process.pid, "started_utc": utc(),
                 "started_elapsed_ns": time.monotonic_ns() - self.epoch, "forced_kill": False}
        with self.lock:
            self.records[role] = entry
            self.commands.append({"role": role, "argv": command})
        return process

    def sample(self):
        with (self.directory / "resources.jsonl").open("x") as stream:
            while not self.stopping.is_set():
                with self.lock:
                    roles = {entry["pid"]: role for role, entry in self.records.items()
                             if entry["process"].poll() is None}
                if roles:
                    try:
                        result = subprocess.run(["ps", "-o", "pid=", "-o", "rss=", "-o", "%cpu=", "-p",
                                                 ",".join(map(str, roles))], capture_output=True, text=True, timeout=2)
                        now = time.monotonic_ns() - self.epoch
                        for line in result.stdout.splitlines():
                            fields = line.split()
                            if len(fields) != 3 or int(fields[0]) not in roles:
                                continue
                            pid, rss, cpu = int(fields[0]), int(fields[1]), float(fields[2])
                            record = {"elapsed_ns": now, "role": roles[pid], "pid": pid,
                                      "rss_kib": rss, "ps_cpu_percent": cpu}
                            self.samples.append(record)
                            stream.write(json.dumps(record) + "\n")
                        stream.flush()
                    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                        stream.write(json.dumps({"elapsed_ns": time.monotonic_ns() - self.epoch,
                                                 "sampling_error": type(exc).__name__}) + "\n")
                self.stopping.wait(.2)

    def stop(self, role):
        entry = self.records.get(role)
        if not entry:
            return
        process = entry["process"]
        if process.poll() is None:
            entry["sigterm_utc"] = utc()
            entry["sigterm_elapsed_ns"] = time.monotonic_ns() - self.epoch
            process.terminate()
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                entry["forced_kill"] = True
                process.kill()
                process.wait(timeout=4)
        entry["exit_code"] = process.poll()
        entry["observed_stopped_utc"] = utc()
        entry["observed_stopped_elapsed_ns"] = time.monotonic_ns() - self.epoch
        entry["log"].flush()

    def finish(self):
        # Stop applications first; relay counts and capture_stopped flush last.
        for role in ("benchmark", "client", "server", "origin", "relay", "init"):
            self.stop(role)
        self.stopping.set()
        self.sampler.join(timeout=4)
        if self.sampler.is_alive():
            raise RuntimeError("resource sampler did not stop")
        records = {role: {k: v for k, v in entry.items() if k not in ("process", "log")}
                   for role, entry in self.records.items()}
        for entry in self.records.values():
            entry["log"].close()
        peaks = {}
        for role in records:
            values = [x for x in self.samples if x["role"] == role]
            peaks[role] = {"samples": len(values), "rss_sampled_peak_kib": max((x["rss_kib"] for x in values), default=None)}
        return records, peaks


def sanitized_config(config):
    allowed = ("rate_mbps", "priority", "adaptive", "window_bytes", "max_flows", "max_sessions",
               "heartbeat_ms", "dead_ms", "resume_seconds", "dial_timeout_ms", "test_rotate_seconds",
               "allow_private_targets", "web_padding", "experimental_pin_only")
    return {key: config[key] for key in allowed if key in config}


def publish_evidence(private, output):
    files = {}
    for name in ("events.jsonl", "events.summary.json", "resources.jsonl"):
        path = private / name
        if not path.exists():
            continue
        if name.endswith(".jsonl"):
            values = [json.loads(line) for line in path.read_text().splitlines() if line]
            text = "".join(json.dumps(redact(x, private, output), separators=(",", ":")) + "\n" for x in values)
            (output / name).write_text(text)
        else:
            write_json(output / name, redact(json.loads(path.read_text()), private, output))
        files[name] = {"private_original_sha256": sha(path), "published_sha256": sha(output / name),
                       "redaction": "paths only; workload values, failures and censoring unchanged"}
    capture = private / "capture/capture.jsonl"
    if capture.exists():
        events = [json.loads(line) for line in capture.read_text().splitlines() if line]
        safe = [x for x in events if x["kind"] != "private_udp_mapping"]
        if any("data_base64" in x for x in safe):
            raise RuntimeError("zero-capture study unexpectedly retained payload")
        dest = output / "relay-events.jsonl"
        dest.write_text("".join(json.dumps(x, separators=(",", ":")) + "\n" for x in safe))
        files[dest.name] = {"private_original_sha256": sha(capture), "published_sha256": sha(dest),
                            "redaction": "private_udp_mapping events omitted; all count/error/lifecycle events retained"}
    return files


def run_trial(args, frozen, case, repeat, order):
    network, padding = CASES[case]
    ident = f"{args.label}-{order:02d}-r{repeat}-{case}"
    private, output = args.private / ident, args.out / ident
    private.mkdir(mode=0o700)
    output.mkdir()
    trial = {"trial_id": ident, "case": case, "network": network, "padding": padding,
             "repeat": repeat, "order": order, "started_utc": utc(), "status": "running",
             "configured_duration_seconds": args.duration, "prebenchmark_idle_seconds": .3}
    group = TrialProcesses(private)
    write_json(output / "trial.json", trial)
    try:
        backend = unused_port("udp" if network in ("h3", "quic") else "tcp")
        socks_port, http_port, echo_port = unused_port(), unused_port(), unused_port()
        if len({backend, socks_port, http_port, echo_port}) != 4:
            raise RuntimeError("ephemeral port allocation collision; trial retained")
        config_dir = private / "config"
        init_cmd = [str(frozen["protox"]), "init", "-dir", str(config_dir), "-host", "127.0.0.1",
                    "-server-name", "webbench.example.test", "-tls-port", str(backend), "-quic-port", str(backend)]
        if network in ("tls", "quic"):
            init_cmd.append("--legacy")
        proc = group.start("init", init_cmd)
        if proc.wait(timeout=8) != 0:
            raise RuntimeError("configuration generation failed")
        server = json.loads((config_dir / "server.json").read_text())
        client = json.loads((config_dir / "client.json").read_text())
        common = {"max_flows": 32, "window_bytes": 65536, "priority": True, "adaptive": False, "web_padding": padding}
        server.update(common, rate_mbps=8, allow_private_targets=True)
        client.update(common, rate_mbps=2, socks_listen=f"127.0.0.1:{socks_port}")
        for field in ("web_listen", "http3_listen", "tls_listen", "quic_listen"):
            server.pop(field, None)
        listener = {"h2": "web_listen", "h3": "http3_listen", "tls": "tls_listen", "quic": "quic_listen"}[network]
        server[listener] = f"127.0.0.1:{backend}"
        write_json(config_dir / "server.json", server)
        origin = group.start("origin", [str(frozen["pxbench"]), "serve", "-http", f"127.0.0.1:{http_port}",
                                         "-echo", f"127.0.0.1:{echo_port}"])
        await_condition(origin, lambda: can_connect(http_port) and can_connect(echo_port))
        server_process = group.start("server", [str(frozen["protox"]), "server", "-config", str(config_dir / "server.json")])
        ready_message = {"h2": "HTTPS listener ready", "h3": "HTTP/3 listener ready",
                         "tls": "TLS listener ready", "quic": "QUIC listener ready"}[network]
        await_condition(server_process, lambda: ready_message in (private / "server.log").read_text())
        relay_target = "--udp-target" if network in ("h3", "quic") else "--tcp-target"
        relay = group.start("relay", [sys.executable, str(frozen["relay"]), "--out", str(private / "capture"),
                                      "--label", case, relay_target, f"127.0.0.1:{backend}",
                                      "--capture-bytes", "0", "--capture-packets", "0"])
        ready = private / "capture/ready.json"
        await_condition(relay, ready.exists)
        endpoint = json.loads(ready.read_text())["udp_listen" if network in ("h3", "quic") else "tcp_listen"]
        client["endpoints"] = [{"network": network, "address": f"{endpoint[0]}:{endpoint[1]}",
                                "server_name": "proto-x.local" if network in ("tls", "quic") else "webbench.example.test"}]
        write_json(config_dir / "client.json", client)
        trial["config_summary"] = {"server": sanitized_config(server), "client": sanitized_config(client),
                                    "single_endpoint": network, "ech": False, "http_keepalive": True,
                                    "capture_bytes": 0, "capture_packets": 0,
                                    "trust": "explicit development leaf pin; no public CA/ECH claim"}
        trial["private_config_sha256"] = {"server": sha(config_dir / "server.json"), "client": sha(config_dir / "client.json")}
        client_process = group.start("client", [str(frozen["protox"]), "client", "-config", str(config_dir / "client.json")])
        await_condition(client_process, lambda: "SOCKS5 listener ready" in (private / "client.log").read_text())
        time.sleep(.3)
        trial["benchmark_started_utc"] = utc()
        trial["benchmark_started_elapsed_ns"] = time.monotonic_ns() - group.epoch
        benchmark = group.start("benchmark", [str(frozen["pxbench"]), "run", "-proxy", f"127.0.0.1:{socks_port}",
                  "-http-target", f"http://127.0.0.1:{http_port}", "-echo-target", f"127.0.0.1:{echo_port}",
                  "-duration", f"{args.duration}s", "-timeout", "3s", "-rps", "5", "-http-method", "POST",
                  "-http-bytes", "1024", "-concurrency", "32", "-echo-interval", "100ms", "-stream-interval", "50ms",
                  "-background", "1", "-background-mbps", "2", "-uploads", "0", "-run-id", ident,
                  "-output", str(private / "events.jsonl"), "-summary", str(private / "events.summary.json")])
        code = benchmark.wait(timeout=args.duration + 10)
        trial["benchmark_ended_utc"] = utc()
        trial["benchmark_ended_elapsed_ns"] = time.monotonic_ns() - group.epoch
        if code != 0:
            raise RuntimeError(f"benchmark exited {code}")
        for role in ("client", "server", "relay", "origin"):
            if group.records[role]["process"].poll() is not None:
                raise RuntimeError(f"{role} terminated unexpectedly during workload")
        trial["status"] = "completed"
    except KeyboardInterrupt:
        trial.update(status="interrupted", error="runner interrupted; owned processes cleaned up")
    except Exception as exc:
        trial.update(status="failed", error=redact(f"{type(exc).__name__}: {exc}", private, output))
    finally:
        records, peaks = group.finish()
        trial["processes"] = records
        trial["resources"] = peaks
        trial["resource_notes"] = ["200ms requested sampling interval; actual timestamps retained.",
                                   "Sampled RSS peak is a lower bound, not OS high-water RSS.",
                                   "ps %cpu is not interval CPU accounting; raw values are diagnostic only."]
        trial["commands"] = redact(group.commands, args.private, args.out)
        write_json(private / "commands.json", group.commands)
        try:
            trial["evidence_files"] = publish_evidence(private, output)
        except Exception as exc:
            trial["status"] = "failed"
            trial["evidence_error"] = redact(f"{type(exc).__name__}: {exc}", private, output)
        trial["ended_utc"] = utc()
        write_json(output / "trial.json", trial)
    print(json.dumps({"trial": ident, "status": trial["status"], "error": trial.get("error"),
                      "output": str(output.relative_to(ROOT))}), flush=True)
    return trial


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protox", required=True, type=Path)
    parser.add_argument("--pxbench", required=True, type=Path)
    parser.add_argument("--protox-sha256", required=True, help="expected reviewed binary hash")
    parser.add_argument("--private", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--label", required=True)
    parser.add_argument("--duration", type=float, default=12)
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--cases", nargs="+", choices=list(CASES), default=list(CASES))
    parser.add_argument("--pilot", action="store_true", help="label the entire invocation as pilot, never formal")
    args = parser.parse_args()
    args.private, args.out = args.private.resolve(), args.out.resolve()
    if not args.private.is_relative_to(ROOT / ".local"):
        parser.error("private outputs must be inside this repository's ignored .local directory")
    if not args.out.is_relative_to(ROOT / "results"):
        parser.error("public output must be inside this repository's results directory")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", args.label):
        parser.error("label must be a redacted ASCII identifier")
    if not .1 <= args.duration <= 3600 or not 1 <= args.rounds <= 20:
        parser.error("duration must be 0.1..3600s and rounds 1..20")
    if sha(args.protox.resolve()) != args.protox_sha256:
        parser.error("candidate hash does not match reviewed expected binary")
    os.umask(0o077)
    args.private.mkdir(parents=True, exist_ok=False, mode=0o700)
    args.out.mkdir(parents=True, exist_ok=False)
    snapshots = args.private / "frozen"
    snapshots.mkdir()
    frozen = {}
    for name, source in (("protox", args.protox.resolve()), ("pxbench", args.pxbench.resolve()),
                         ("relay", ROOT / "tools/recognition/relay.py")):
        destination = snapshots / ("relay.py" if name == "relay" else name)
        shutil.copy2(source, destination)
        frozen[name] = destination
    if sha(frozen["protox"]) != args.protox_sha256:
        raise RuntimeError("candidate changed while freezing")
    sources = sorted(set(ROOT.glob("internal/**/*.go")) | set(ROOT.glob("cmd/**/*.go")) |
                     {ROOT / "go.mod", ROOT / "go.sum", HERE / "run.py", HERE / "summarize.py"})
    source_hashes = {}
    source_dir = snapshots / "source"
    for path in sources:
        data = path.read_bytes()
        relative = path.relative_to(ROOT)
        destination = source_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        source_hashes[str(relative)] = hashlib.sha256(data).hexdigest()
    def info(command):
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=15)
        return {"argv": redact(command, args.private, args.out), "exit_code": result.returncode,
                "stdout": redact(result.stdout, args.private, args.out), "stderr": redact(result.stderr, args.private, args.out)}
    manifest = {"schema": 1, "label": args.label, "pilot": args.pilot, "created_utc": utc(),
                "scope": "real loopback SOCKS workloads; no network impairment; carrier/padding cost diagnostic",
                "binaries_sha256": {name: sha(path) for name, path in frozen.items()},
                "build_info": {name: info(["go", "version", "-m", str(frozen[name])]) for name in ("protox", "pxbench")},
                "version": info([str(frozen["protox"]), "version"]), "git_head": info(["git", "rev-parse", "HEAD"]),
                "platform": {"system": platform.system(), "release": platform.release(), "machine": platform.machine(),
                             "python": platform.python_version(), "logical_cpus": os.cpu_count()},
                "source_snapshot_sha256": source_hashes,
                "source_snapshot_note": "Source state at freeze time, not independent proof that supplied binaries were built from this exact snapshot.",
                "runner_sha256": sha(HERE / "run.py"), "parameters": vars(args) | {"protox": str(args.protox), "pxbench": str(args.pxbench),
                                               "private": "$PRIVATE", "out": "$RESULTS"},
                "interpretation": ["Same frozen executables and same forwarding relay for every trial.",
                    "8/2 Mbps application sender budgets are not total carrier wire-rate caps.",
                    "1 source-paced 2 Mbps download plus HTTP, persistent echo and SSE; HTTP keepalive on.",
                    "Reverse case order on even rounds; fresh origin/server/client/relay per trial.",
                    "Relay interval includes handshake, 300ms prebenchmark idle, workload and shutdown.",
                    "TCP bytes count actual TLS bytes read; chunks are not packets or retransmissions.",
                    "UDP bytes count actual datagram payload, excluding UDP/IP headers and NIC framing.",
                    "Zero capture retains counts; capture_truncated means payload retention omitted, not packet loss.",
                    "No weak-network superiority, anonymity or classifier conclusion follows from these loopback trials."]}
    manifest = redact(manifest, args.private, args.out)
    write_json(args.out / "manifest.json", manifest)
    trials = []
    try:
        for repeat in range(1, args.rounds + 1):
            cases = args.cases if repeat % 2 else list(reversed(args.cases))
            for case in cases:
                trials.append(run_trial(args, frozen, case, repeat, len(trials) + 1))
                write_json(args.out / "index.json", [{k: t.get(k) for k in ("trial_id", "case", "repeat", "order", "status", "error")} for t in trials])
                if trials[-1]["status"] == "interrupted":
                    raise KeyboardInterrupt
    finally:
        manifest["ended_utc"] = utc()
        manifest["completed_trials"] = len(trials)
        manifest["all_planned_trials_attempted"] = len(trials) == len(args.cases) * args.rounds
        manifest["frozen_sha256_after"] = {name: sha(path) for name, path in frozen.items()}
        write_json(args.out / "manifest.json", manifest)
    return 1 if any(t["status"] != "completed" for t in trials) else 0


if __name__ == "__main__":
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupt)
    raise SystemExit(main())
