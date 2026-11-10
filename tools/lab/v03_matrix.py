#!/usr/bin/env python3
"""v0.3 comparisons on the dedicated Linux netlab, including real UDP faults.

All TCP/UDP/IP traffic shares the same tc link. This is controlled emulation,
not field censorship evidence. Configuration and executable inputs are staged
privately; every run records their non-secret parameters and binary hashes.
"""
import argparse
import json
import os
from pathlib import Path
import random
import signal
import subprocess
import threading
import time

from matrix import Matrix, Processes, Sampler, SIDES, counters, ns, run, sha, utc, write


VARIANTS = ["v02", "fixed", "adaptive", "no-prepare", "age", "count", "age-no-prepare", "causal", "probe-only", "joint", "xray-vision", "hy-bbr-standard"]
PROFILES = {
    "healthy": dict(rtt=60, jitter=0, loss=0, up=2, down=8),
    "loss1": dict(rtt=60, jitter=5, loss=1, up=2, down=8),
    "high-rtt": dict(rtt=500, jitter=20, loss=0, up=2, down=8),
    "blackhole": dict(rtt=100, jitter=0, loss=0, up=2, down=8),
    "pulse": dict(rtt=100, jitter=0, loss=0, up=2, down=8),
    "up-blackhole": dict(rtt=100, jitter=0, loss=0, up=2, down=8),
}


class TracedProcesses(Processes):
    """Retain raw logs privately; timestamp and whitelist research events."""
    def __init__(self, directory, private):
        super().__init__(directory)
        self.private = private
        private.mkdir(parents=True, mode=0o700, exist_ok=False)
        self.readers = []
        self.events = []

    def start(self, role, side, command):
        proc = subprocess.Popen(ns(side, command), stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, start_new_session=True)
        self.procs[role] = proc
        self.commands[role] = ns(side, command)

        def read():
            with (self.private / f"{role}.log").open("x") as log:
                os.chmod(log.name, 0o600)
                for line in proc.stdout:
                    now, wall = time.monotonic_ns(), time.time_ns()
                    log.write(line)
                    log.flush()
                    if role not in ("client", "server"):
                        continue
                    try:
                        data = json.loads(line)
                    except (ValueError, TypeError):
                        continue
                    # Do not publish addresses, session secrets, or arbitrary
                    # error strings. Numeric diagnostics and known event fields
                    # are sufficient for recovery critical-path analysis.
                    row = {"role": role, "observed_mono_ns": now, "observed_wall_ns": wall}
                    for k, value in data.items():
                        if isinstance(value, (int, float, bool)) or k in (
                                "time", "msg", "event", "carrier", "reason", "alpn"):
                            row[k] = value
                    self.events.append(row)

        thread = threading.Thread(target=read)
        thread.start()
        self.readers.append(thread)
        return proc

    def stop(self):
        super().stop()
        for reader in self.readers:
            reader.join(timeout=4)
            if reader.is_alive():
                raise RuntimeError("proxy log reader did not stop")
        write(self.directory / "proxy-events.json", sorted(self.events, key=lambda e:e["observed_mono_ns"]))


class ResearchMatrix(Matrix):
    def services(self, variant, procs):
        baseline = self.private / "baseline"
        procs.start("fixture", "server", [self.bin / "recoverybench", "-fixture",
                    "-fixture-http", "127.0.0.1:18443", "-fixture-echo", "127.0.0.1:18081",
                    "-fixture-cert", baseline / "tls-cert.pem", "-fixture-key", baseline / "tls-key.pem",
                    "-fixture-log", procs.directory / "target-events.jsonl"])
        if variant == "xray-vision":
            procs.start("cover", "server", [self.bin / "tlscover", "-listen", "127.0.0.1:39443",
                        "-cert", baseline / "tls-cert.pem", "-key", baseline / "tls-key.pem"])
            procs.start("server", "server", [self.bin / "xray", "run", "-config", baseline / "xray-server.json"])
            time.sleep(.15)
            procs.start("client", "client", [self.bin / "xray", "run", "-config", baseline / "xray-client.json"])
            return 10801
        if variant == "hy-bbr-standard":
            procs.start("server", "server", [self.bin / "hysteria", "server", "--config", baseline / "hysteria-server-bbr-standard.json"])
            time.sleep(.15)
            procs.start("client", "client", [self.bin / "hysteria", "client", "--config", baseline / "hysteria-client-bbr-standard.json"])
            return 10802
        binary = self.bin / ("protox-v02" if variant == "v02" else "protox-candidate")
        px = self.private / "px"
        procs.start("server", "server", [binary, "server", "-config", px / f"server-{variant}.json"])
        time.sleep(.15)
        procs.start("client", "client", [binary, "client", "-config", px / f"client-{variant}.json"])
        return 1088

    def silent_udp_fault(self, direction):
        # Output DROP can return EPERM to a local UDP sender. Input DROP at
        # the receiver is a silent network blackhole, with no local send error.
        self.clear_fault()
        sides = ("server",) if direction == "up" else ("client",) if direction == "down" else ("client", "server")
        for side in sides:
            dev = "pxlinkc" if side == "client" else "pxlinks"
            run(ns(side, ["nft", "add", "table", "inet", "protox_fault"]))
            run(ns(side, ["nft", "add", "chain", "inet", "protox_fault", "in",
                          "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"]))
            run(ns(side, ["nft", "add", "rule", "inet", "protox_fault", "in",
                          "iifname", dev, "meta", "l4proto", "udp", "counter", "drop"]))

    def clear_fault(self):
        for side in ("client", "server"):
            run(ns(side, ["nft", "delete", "table", "inet", "protox_fault"]), check=False)

    def fault_counters(self):
        result = {}
        for side in ("client", "server"):
            got = run(ns(side, ["nft", "-j", "list", "table", "inet", "protox_fault"]), check=False)
            if got.returncode == 0:
                result[side] = json.loads(got.stdout)
        return result

    def profile(self, name, seed, directory):
        for side, dev in (("client", "pxlinkc"), ("server", "pxlinks")):
            run(ns(side, ["ethtool", "-K", dev, "tso", "off", "gso", "off", "gro", "off",
                          "tx-udp-segmentation", "off", "tx-gso-list", "off"]))
            run(ns(side, ["tc", "qdisc", "del", "dev", dev, "root"]), check=False)
        args = self.lab + ["profile", "--seed", str(seed), "--queue-ms", str(self.a.queue_ms)]
        for key, value in PROFILES[name].items():
            args += ["--" + key, str(value)]
        write(directory / "profile.json", json.loads(run(args).stdout))
        run(self.lab + ["unblock-udp"])

    def bench_cmd(self, port, duration, prefix, trial_id):
        # All variants get the same paced source, semantic workload and timeout.
        return super().bench_cmd(port, duration, prefix, trial_id) + ["-cold-http"]

    def one(self, index, variant, profile, seed):
        trial_id = f"{index:02d}-{profile}-{variant}-s{seed}"
        directory = self.out / trial_id
        directory.mkdir()
        manifest = dict(trial_id=trial_id, variant=variant, profile=profile, seed=seed,
                        utc_start=utc(), status="running", duration_s=self.a.duration,
                        warmup_s=self.a.warmup, gomaxprocs=1,
                        background_workers=self.a.background,
                        background_mbps_source_budget=self.a.background_mbps)
        write(directory / "trial.json", manifest)
        processes, sampler = TracedProcesses(directory, self.private / "runs" / self.a.run_id / trial_id), None
        stop_fault, fault_thread = threading.Event(), None
        fault_events = []
        epoch = time.monotonic_ns()

        def event(kind, **values):
            now = time.monotonic_ns()
            fault_events.append(dict(event=kind, elapsed_ns=now-epoch, mono_ns=now,
                                     wall_ns=time.time_ns(), utc=utc(), **values))
            write(directory / "fault-events.json", fault_events)

        def inject():
            if stop_fault.wait(self.a.fault_after):
                return
            try:
                event("fault_install_begin")
                self.silent_udp_fault("up" if profile == "up-blackhole" else "both")
                event("fault_installed", direction="up" if profile == "up-blackhole" else "both", hook="receiver_input")
                stop_fault.wait(.2 if profile == "pulse" else self.a.fault_for)
            except Exception as exc:
                event("fault_error", error=f"{type(exc).__name__}: {exc}")
            finally:
                event("fault_remove_begin")
                write(directory / "fault-counters.json", self.fault_counters())
                self.clear_fault()
                event("fault_removed")

        try:
            self.profile(profile, seed, directory)
            before_start = self.snapshot(directory / "link-before-startup.json")
            port = self.services(variant, processes)
            time.sleep(.5)
            processes.alive()
            if self.a.warmup:
                warm = run(ns("client", self.bench_cmd(port, self.a.warmup, directory/"warmup", trial_id+"-warmup")),
                           check=False, timeout=self.a.warmup+12)
                (directory/"warmup.stdout").write_text(warm.stdout)
                (directory/"warmup.stderr").write_text(warm.stderr)
                manifest["warmup_exit_code"] = warm.returncode
            processes.alive()
            before = self.snapshot(directory / "link-before.json")
            epoch = time.monotonic_ns()
            event("workload_launch")
            benchmark_lower = time.monotonic_ns()
            workload = processes.start("workload", "client", self.bench_cmd(port, self.a.duration, directory/"events", trial_id))
            # Bracket the benchmark's monotonic epoch without trusting wall
            # clock synchronization. Its first persisted event carries elapsed
            # monotonic time; publication is necessarily before our observation.
            for _ in range(1000):
                try:
                    with (directory/"events.jsonl").open() as first:
                        line = first.readline()
                    observed = time.monotonic_ns()
                    initial = json.loads(line)
                    if initial.get("kind") == "run_start":
                        benchmark_upper = observed-initial["recorded_elapsed_ns"]
                        manifest["benchmark_epoch_mono_bounds"] = dict(lower_ns=benchmark_lower,
                                    upper_ns=benchmark_upper, width_ns=benchmark_upper-benchmark_lower)
                        break
                except (FileNotFoundError, ValueError):
                    pass
                if workload.poll() is not None:
                    break
                time.sleep(.001)
            sampler = Sampler(dict(processes.procs), directory/"resources.jsonl")
            sampler.start()
            if profile in ("blackhole", "up-blackhole", "pulse"):
                fault_thread = threading.Thread(target=inject)
                fault_thread.start()
            try:
                code = workload.wait(timeout=self.a.duration+15)
            except subprocess.TimeoutExpired:
                manifest["runner_timeout"] = True
                raise
            manifest["workload_exit_code"] = code
            event("workload_exit", exit_code=code)
            stop_fault.set()
            if fault_thread:
                fault_thread.join(timeout=12)
                if fault_thread.is_alive():
                    raise RuntimeError("fault cleanup did not finish")
            write(directory/"resource-summary.json", sampler.stop())
            sampler = None
            after = self.snapshot(directory/"link-after.json")
            write(directory/"link-delta.json", counters(before, after))
            write(directory/"link-startup-warmup-delta.json", counters(before_start, before))
            manifest["status"] = "completed" if code == 0 else "workload_failed"
            if any(e["event"] == "fault_error" for e in fault_events):
                manifest["status"] = "fault_failed"
            summary = directory/"events.summary.json"
            if summary.exists():
                data = json.loads(summary.read_text())
                manifest["observed"] = {k: data.get(k) for k in ("operations", "sse", "download_goodput_mbps")}
            manifest["commands"] = processes.commands
        except Exception as exc:
            manifest["status"] = "runner_error"
            manifest["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            stop_fault.set()
            if fault_thread:
                fault_thread.join(timeout=12)
            self.clear_fault()
            if sampler is not None:
                write(directory/"resource-summary.json", sampler.stop())
            processes.stop()
            manifest["utc_end"] = utc()
            write(directory/"trial.json", manifest)
            self.rows.append(manifest)
            write(self.out/"index.json", self.rows)
        brief = {k: manifest.get(k) for k in ("trial_id", "status", "error")}
        print(json.dumps(brief), flush=True)

    def execute(self):
        existing = run(["ip", "netns", "list"]).stdout
        if not all(name in existing.split() for name in SIDES.values()):
            raise RuntimeError("initialize the dedicated netlab first")
        hosts = Path("/etc/hosts")
        if "protox-baseline.test" not in hosts.read_text():
            with hosts.open("a") as f:
                f.write("\n127.0.0.1 protox-baseline.test # PROTO-X controlled lab origin\n")
        schedule = [(v, p, s) for s in self.a.seeds for p in self.a.profiles for v in self.a.variants]
        random.Random(self.a.schedule_seed).shuffle(schedule)
        meta = dict(created_utc=utc(), source="dedicated Linux VM, tc netem, real IP packets",
                    kernel=run(["uname", "-a"]).stdout.strip(), parameters=vars(self.a),
                    binaries_sha256={p.name:sha(p) for p in self.bin.iterdir() if p.is_file()},
                    scripts_sha256={p:sha(self.root/p) for p in ("v03_matrix.py", "matrix.py", "netlab.py")},
                    public_parameters=json.loads((self.root/"public-parameters.json").read_text()),
                    schedule=[dict(variant=v, profile=p, seed=s) for v,p,s in schedule],
                    notes=["tc accounts shared outer traffic, including padding, probes, recovery and retransmissions.",
                           "qdisc deltas are veth Ethernet-frame bytes including the 14-byte MAC header, excluding FCS; startup/warmup separate.",
                           "netem rate adds its configured 24-byte per-packet overhead for shaping; that addition is not included in qdisc byte counters.",
                           "No equal-fallback claim: Xray uses TCP; Hysteria has no H2 standby in these configs.",
                           "Faults silently drop incoming UDP at the receiving namespace; output-drop send errors are avoided.",
                           "Fault install/remove timestamps bracket kernel command completion, not exact packet loss onset.",
                           "Proxy event receipt and fault events share a VM monotonic clock; JSON log delivery is an upper bound.",
                           "VPS management and host network are outside these two namespaces."])
        write(self.out/"manifest.json", meta)
        for index, (variant, profile, seed) in enumerate(schedule, 1):
            self.one(index, variant, profile, seed)
        meta.update(finished_utc=utc(), completed_trials=len(self.rows))
        write(self.out/"manifest.json", meta)
        return 0 if all(r["status"] == "completed" for r in self.rows) else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default="/tmp/pxlab-v03")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--seeds", nargs="+", type=int, default=[401, 402, 403])
    ap.add_argument("--schedule-seed", type=int, default=74031)
    ap.add_argument("--variants", nargs="+", choices=VARIANTS, default=VARIANTS)
    ap.add_argument("--profiles", nargs="+", choices=list(PROFILES), default=["healthy", "blackhole"])
    ap.add_argument("--duration", type=float, default=16)
    ap.add_argument("--warmup", type=float, default=3)
    ap.add_argument("--queue-ms", type=float, default=75)
    ap.add_argument("--background", type=int, default=1)
    ap.add_argument("--background-mbps", type=float, default=2)
    ap.add_argument("--fault-after", type=float, default=5)
    ap.add_argument("--fault-for", type=float, default=6)
    a = ap.parse_args()
    if os.geteuid() != 0:
        ap.error("run only as root inside the dedicated lab VM")
    if not a.run_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for c in a.run_id):
        ap.error("unsafe run-id")
    if a.duration <= a.fault_after+a.fault_for or min(a.duration, a.fault_after, a.fault_for) <= 0:
        ap.error("duration must allow a completed fault and recovery observation")
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    raise SystemExit(ResearchMatrix(a).execute())


if __name__ == "__main__":
    main()
