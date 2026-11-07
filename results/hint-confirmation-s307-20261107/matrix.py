#!/usr/bin/env python3
"""Run an explicitly staged protocol matrix inside the dedicated Linux VM.

All workloads traverse the same actual packet-level link. Never logs secret
configuration fields. Warmup is a separate workload invocation; the proxy
process and its reusable outer connection remain running for measurement.
"""
import argparse
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import random
import signal
import subprocess
import sys
import threading
import time

VARIANTS = ["px-priority", "px-fifo", "px-adaptive", "xray-vision",
            "hy-bbr-standard", "hy-bbr-conservative", "hy-brutal8", "hy-brutal6"]
PROFILES = {"healthy": {"rtt": 60, "jitter": 0, "loss": 0, "up": 2, "down": 8},
            "loss1-jitter5": {"rtt": 60, "jitter": 5, "loss": 1, "up": 2, "down": 8}}
SIDES = {"client": "px-client", "server": "px-server"}


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def write(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def run(cmd, check=True, timeout=15):
    return subprocess.run([str(x) for x in cmd], text=True, capture_output=True,
                          check=check, timeout=timeout)


def ns(side, cmd):
    return ["ip", "netns", "exec", SIDES[side], "env", "GOMAXPROCS=1"] + [str(x) for x in cmd]


def stat(pid):
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
        fields = raw[raw.rfind(")") + 2:].split()
        resident = int(Path(f"/proc/{pid}/statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE")
        return {"cpu_seconds": (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK"),
                "rss_bytes": resident, "threads": int(fields[17])}
    except (FileNotFoundError, ProcessLookupError):
        return None


class Processes:
    def __init__(self, directory):
        self.directory = directory
        self.procs = {}
        self.logs = []
        self.commands = {}

    def start(self, role, side, command):
        log = open(self.directory / f"{role}.log", "w")
        self.logs.append(log)
        proc = subprocess.Popen(ns(side, command), stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
        self.procs[role] = proc
        self.commands[role] = ns(side, command)
        return proc

    def alive(self):
        for role, proc in self.procs.items():
            if proc.poll() is not None:
                raise RuntimeError(f"{role} exited early with {proc.returncode}; see its retained log")

    def stop(self):
        for proc in self.procs.values():
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
        deadline = time.monotonic() + 3
        for proc in self.procs.values():
            try:
                proc.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
        for log in self.logs:
            log.close()


class Sampler:
    def __init__(self, procs, path):
        self.procs = procs
        self.path = path
        self.samples = []
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.loop)

    def loop(self):
        start = time.monotonic()
        with open(self.path, "w") as f:
            while not self.done.is_set():
                row = {"elapsed_s": time.monotonic() - start,
                       "processes": {k: stat(v.pid) for k, v in self.procs.items()}}
                self.samples.append(row)
                f.write(json.dumps(row) + "\n")
                self.done.wait(0.1)

    def start(self):
        self.thread.start()

    def stop(self):
        self.done.set()
        self.thread.join()
        out = {"sampling_interval_s": 0.1, "roles": {}}
        for role in self.procs:
            values = [(x["elapsed_s"], x["processes"][role]) for x in self.samples if x["processes"].get(role)]
            if not values:
                continue
            duration = values[-1][0] - values[0][0]
            cpu = values[-1][1]["cpu_seconds"] - values[0][1]["cpu_seconds"]
            out["roles"][role] = {"samples": len(values), "sampled_seconds": duration,
                                  "cpu_seconds_delta": cpu,
                                  "cpu_percent_one_core": 100 * cpu / duration if duration else None,
                                  "rss_peak_bytes": max(x[1]["rss_bytes"] for x in values),
                                  "rss_mean_bytes": sum(x[1]["rss_bytes"] for x in values) / len(values),
                                  "rss_last_bytes": values[-1][1]["rss_bytes"]}
        return out


def counters(before, after):
    out = {}
    for name in SIDES.values():
        b = next(x for x in before["namespaces"][name]["qdisc"] if x["kind"] == "netem")
        e = next(x for x in after["namespaces"][name]["qdisc"] if x["kind"] == "netem")
        def nstat(snapshot):
            vals = {}
            for line in snapshot["namespaces"][name]["nstat_text"].splitlines():
                f = line.split()
                if len(f) >= 2 and f[1].isdigit():
                    vals[f[0]] = int(f[1])
            return vals
        nb, ne = nstat(before), nstat(after)
        out[name] = {"qdisc": {k: e[k] - b[k] for k in ("bytes", "packets", "drops", "overlimits", "requeues")},
                     "namespace_tcp_retrans_segments_includes_loopback": ne.get("TcpRetransSegs", 0) - nb.get("TcpRetransSegs", 0)}
    return out


class Matrix:
    def __init__(self, args):
        self.a = args
        self.root = Path(args.root).resolve()
        self.bin = self.root / "bin"
        self.private = self.root / "private"
        self.lab = ["python3", str(self.root / "netlab.py")]
        self.out = self.root / "results" / args.run_id
        self.out.mkdir(parents=True, exist_ok=False)
        self.rows = []

    def snapshot(self, path):
        result = json.loads(run(self.lab + ["state"]).stdout)
        write(path, result)
        return result

    def profile(self, name, seed, directory):
        # Clear previous-run queued packets and counters on only our owned link.
        for side, dev in (("client", "pxlinkc"), ("server", "pxlinks")):
            run(ns(side, ["ethtool", "-K", dev, "tso", "off", "gso", "off", "gro", "off",
                          "tx-udp-segmentation", "off", "tx-gso-list", "off"]))
            run(ns(side, ["tc", "qdisc", "del", "dev", dev, "root"]), check=False)
        args = self.lab + ["profile", "--seed", str(seed), "--queue-ms", str(self.a.queue_ms)]
        for k, v in PROFILES[name].items():
            args += ["--" + k, str(v)]
        result = json.loads(run(args).stdout)
        write(directory / "profile.json", result)
        run(self.lab + ["unblock-udp"])

    def services(self, variant, procs):
        baseline = self.private / "baseline"
        procs.start("fixture", "server", [self.bin / "pxbench", "serve", "-http", "",
                    "-https", "127.0.0.1:18443", "-echo", "127.0.0.1:18081",
                    "-cert", baseline / "tls-cert.pem", "-key", baseline / "tls-key.pem"])
        if variant.startswith("px-"):
            px = self.private / "px"
            procs.start("server", "server", [self.bin / "protox", "server", "-config", px / f"server-{variant}.json"])
            time.sleep(0.15)
            procs.start("client", "client", [self.bin / "protox", "client", "-config", px / f"client-{variant}.json"])
            return 1088
        if variant == "xray-vision":
            procs.start("cover", "server", [self.bin / "tlscover", "-listen", "127.0.0.1:39443",
                                            "-cert", baseline / "tls-cert.pem", "-key", baseline / "tls-key.pem"])
            procs.start("server", "server", [self.bin / "xray", "run", "-config", baseline / "xray-server.json"])
            time.sleep(0.15)
            procs.start("client", "client", [self.bin / "xray", "run", "-config", baseline / "xray-client.json"])
            return 10801
        profile = variant.removeprefix("hy-")
        procs.start("server", "server", [self.bin / "hysteria", "server", "--config", baseline / f"hysteria-server-{profile}.json"])
        time.sleep(0.15)
        procs.start("client", "client", [self.bin / "hysteria", "client", "--config", baseline / f"hysteria-client-{profile}.json"])
        return 10802

    def bench_cmd(self, port, duration, prefix, trial_id):
        cmd = [self.bin / "pxbench", "run", "-proxy", f"127.0.0.1:{port}",
               "-http-target", "https://protox-baseline.test:18443", "-echo-target", "127.0.0.1:18081",
               "-ca", self.private / "baseline/tls-cert.pem", "-duration", f"{duration}s",
               "-timeout", "3s", "-rps", "5", "-echo-interval", "100ms", "-stream-interval", "50ms",
               "-background", str(self.a.background), "-uploads", "0", "-output", str(prefix) + ".jsonl",
               "-summary", str(prefix) + ".summary.json", "-run-id", trial_id]
        if self.a.background_mbps is not None:
            cmd += ["-background-mbps", str(self.a.background_mbps)]
        return cmd

    def one(self, index, variant, profile, seed):
        trial_id = f"{index:02d}-{profile}-{variant}-s{seed}"
        directory = self.out / trial_id
        directory.mkdir()
        manifest = {"trial_id": trial_id, "variant": variant, "profile": profile, "seed": seed,
                    "stage": self.a.stage, "utc_start": utc(), "status": "running",
                    "duration_s": self.a.duration, "warmup_s": self.a.warmup,
                    "gomaxprocs": 1, "background_workers": self.a.background,
                    "background_mbps_source_budget": self.a.background_mbps}
        write(directory / "trial.json", manifest)
        processes = Processes(directory)
        sampler = None
        try:
            self.profile(profile, seed, directory)
            before_startup = self.snapshot(directory / "link-before-startup.json")
            port = self.services(variant, processes)
            time.sleep(0.5)
            processes.alive()
            if self.a.warmup:
                warm = run(ns("client", self.bench_cmd(port, self.a.warmup, directory / "warmup", trial_id + "-warmup")),
                           check=False, timeout=self.a.warmup + 10)
                (directory / "warmup.stdout").write_text(warm.stdout)
                (directory / "warmup.stderr").write_text(warm.stderr)
                manifest["warmup_exit_code"] = warm.returncode
            processes.alive()
            before = self.snapshot(directory / "link-before.json")
            resources = {k: v for k, v in processes.procs.items()}
            measurement = processes.start("workload", "client", self.bench_cmd(port, self.a.duration, directory / "events", trial_id))
            resources["workload"] = measurement
            manifest["process_ids"] = {role: proc.pid for role, proc in processes.procs.items()}
            manifest["commands"] = processes.commands
            sampler = Sampler(resources, directory / "resources.jsonl")
            sampler.start()
            try:
                code = measurement.wait(timeout=self.a.duration + 12)
            except subprocess.TimeoutExpired:
                manifest["runner_timeout"] = True
                os.killpg(measurement.pid, signal.SIGTERM)
                try:
                    code = measurement.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(measurement.pid, signal.SIGKILL)
                    code = measurement.wait()
            manifest["workload_exit_code"] = code
            write(directory / "resource-summary.json", sampler.stop())
            sampler = None
            after = self.snapshot(directory / "link-after.json")
            write(directory / "link-delta.json", counters(before, after))
            write(directory / "link-startup-warmup-delta.json", counters(before_startup, before))
            manifest["status"] = "completed" if code == 0 else "workload_failed"
            summary_file = directory / "events.summary.json"
            if summary_file.exists():
                summary = json.loads(summary_file.read_text())
                http = summary.get("operations", {}).get("http", {})
                echo = summary.get("operations", {}).get("echo", {})
                sse = summary.get("sse", {})
                manifest["observed"] = {
                    "http_success": http.get("success", 0), "http_total": http.get("total", 0),
                    "http_fail": http.get("failure", 0), "http_timeout": http.get("timeout", 0),
                    "http_censored": http.get("censored", 0),
                    "http_p95_ms": http.get("successful_latency_ms", {}).get("p95"),
                    "http_p99_ms": http.get("successful_latency_ms", {}).get("p99"),
                    "echo_success": echo.get("success", 0), "echo_total": echo.get("total", 0),
                    "echo_timeout": echo.get("timeout", 0), "echo_p95_ms": echo.get("successful_latency_ms", {}).get("p95"),
                    "sse_tokens": sse.get("tokens", 0), "sse_sequence_errors": sse.get("sequence_errors", 0),
                    "sse_source_errors": sse.get("source_errors", 0),
                    "sse_gap_p95_ms": sse.get("receive_gap_ms", {}).get("p95"),
                    "sse_gap_p99_ms": sse.get("receive_gap_ms", {}).get("p99"),
                    "sse_gap_gt250": sse.get("gaps_over_250ms", 0), "sse_gap_gt1000": sse.get("gaps_over_1000ms", 0),
                    "download_goodput_mbps": summary.get("download_goodput_mbps", 0)}
        except Exception as exc:
            manifest["status"] = "runner_error"
            manifest["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            if sampler is not None:
                write(directory / "resource-summary.json", sampler.stop())
            processes.stop()
            manifest["utc_end"] = utc()
            write(directory / "trial.json", manifest)
            self.rows.append(manifest)
            write(self.out / "index.json", self.rows)
        print(json.dumps(manifest, ensure_ascii=False), flush=True)
        return manifest

    def execute(self):
        existing = run(["ip", "netns", "list"]).stdout
        if not all(name in existing.split() for name in SIDES.values()):
            raise RuntimeError("initialize the dedicated netlab first")
        # Names resolve at the proxy target side; only our controlled test FQDN.
        hosts = Path("/etc/hosts")
        if "protox-baseline.test" not in hosts.read_text():
            with hosts.open("a") as f:
                f.write("\n127.0.0.1 protox-baseline.test # PROTO-X controlled lab origin\n")
        schedule = [(variant, profile, self.a.seed) for profile in self.a.profiles for variant in self.a.variants]
        random.Random(self.a.seed).shuffle(schedule)
        metadata = {"run_id": self.a.run_id, "stage": self.a.stage, "created_utc": utc(),
                    "source": "local Linux VM packet-level emulation; not Russian field data",
                    "kernel": run(["uname", "-a"]).stdout.strip(), "cpu_count": os.cpu_count(),
                    "gomaxprocs": 1, "binaries_sha256": {p.name: sha(p) for p in self.bin.iterdir() if p.is_file()},
                    "matrix_script_sha256": sha(Path(__file__)), "netlab_script_sha256": sha(self.root / "netlab.py"),
                    "go_buildinfo": (self.root / "buildinfo.txt").read_text(),
                    "schedule": [{"variant": v, "profile": p, "seed": s} for v, p, s in schedule],
                    "parameters": vars(self.a),
                    "config_parameters": json.loads((self.root / "public-parameters.json").read_text()),
                    "notes": ["Every protocol uses the same fixed physical link budget; PX also has an application frame pacer.",
                              "A common source-paced background follow-up is needed to isolate generic rate-limiting gains.",
                              "Warmup runs a separate application workload; reusable proxy outer sessions persist into measurement.",
                              "All operation failures/timeouts/censoring are retained; successful-only percentiles cannot be read alone.",
                              "nstat TCP retransmission deltas include all namespace TCP sockets, including loopback proxy/fixture sockets; they do not measure QUIC retransmissions.",
                              "Resource CPU is percent of one core; guest has two vCPUs; GOMAXPROCS=1 per process."]}
        write(self.out / "manifest.json", metadata)
        for index, (variant, profile, seed) in enumerate(schedule, 1):
            self.one(index, variant, profile, seed)
        metadata["finished_utc"] = utc()
        metadata["completed_trials"] = len(self.rows)
        write(self.out / "manifest.json", metadata)
        return 0 if all(x["status"] == "completed" for x in self.rows) else 1


def main():
    def interrupt(signum, frame):
        raise KeyboardInterrupt(f"matrix interrupted by signal {signum}; cleaning up owned processes")
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupt)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="/tmp/pxlab")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--stage", choices=["smoke", "discovery", "confirmation"], default="discovery")
    parser.add_argument("--seed", type=int, default=101)
    parser.add_argument("--duration", type=float, default=25)
    parser.add_argument("--warmup", type=float, default=3)
    parser.add_argument("--queue-ms", type=float, default=100)
    parser.add_argument("--background", type=int, default=1)
    parser.add_argument("--background-mbps", type=float)
    parser.add_argument("--variants", nargs="+", choices=VARIANTS, default=VARIANTS)
    parser.add_argument("--profiles", nargs="+", choices=list(PROFILES), default=list(PROFILES))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run as root only inside the dedicated lab VM")
    if not args.run_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for c in args.run_id):
        raise SystemExit("run-id contains unsafe path characters")
    sys.exit(Matrix(args).execute())


if __name__ == "__main__":
    main()
