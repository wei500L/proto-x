#!/usr/bin/env python3
"""Collect session-disjoint, real-UDP H3 traffic shape and workload evidence.

This starts only owned loopback processes. It never contacts the test VPS.
Private identities/configs/logs remain under .local. Public outputs contain
only workload results and packet direction, length and relative timestamps.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
MODES = ("native", "p0", "p63", "p127", "p255")
SUPPORTED_MODES = MODES + ("ack-p0", "ack-p63", "ack-p127", "ack-p255")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    with path.open("x") as f:
        os.chmod(path, 0o600)
        json.dump(value, f, indent=2)
        f.write("\n")


def port(udp=False):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait(process, predicate):
    deadline = time.monotonic() + 6
    while not predicate():
        if process.poll() is not None:
            raise RuntimeError(f"owned process exited {process.returncode}")
        if time.monotonic() > deadline:
            raise RuntimeError("readiness timeout")
        time.sleep(.02)


class Processes:
    def __init__(self, private):
        self.private = private
        self.items = []

    def start(self, role, argv):
        f = (self.private / (role + ".log")).open("x")
        p = subprocess.Popen(list(map(str, argv)), cwd=ROOT, stdout=f, stderr=subprocess.STDOUT)
        self.items.append((role, p, f))
        return p

    def close(self):
        statuses = {}
        for role, p, f in reversed(self.items):
            forced = False
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=4)
                    forced = True
            f.close()
            statuses[role] = {"exit": p.returncode, "forced_kill": forced}
        return statuses


def one(args, frozen, base, identity, group, mode, order):
    ident = f"g{group:03d}-{order}-{mode}"
    private, out = args.private / ident, args.out / ident
    private.mkdir(mode=0o700)
    out.mkdir()
    procs = Processes(private)
    epoch = time.monotonic_ns()
    meta = {"schema": 1, "id": ident, "group": group,
            "split": "train" if group < args.train_groups else "heldout",
            "mode": mode, "order_in_group": order,
            "started_utc": datetime.now(timezone.utc).isoformat(),
            "seed": args.seed_base + group, "status": "running"}
    rng = random.Random(args.seed_base + group)
    workload = {"rps": rng.choice((4., 6., 8.)),
                "http_bytes": rng.choice((384, 768, 1024, 1536)),
                "sse_interval_ms": rng.choice((40, 50, 70)),
                "background_mbps": rng.choice((1.2, 1.6, 2.0)),
                "duration_ms": round(args.duration * 1000), "seed": args.seed_base + group}
    meta["workload"] = workload
    meta["relay"] = {"one_way_delay_ms": args.delay_ms,
                     "up_ipv4_mbps": 2., "down_ipv4_mbps": 8.}
    write(out / "start.json", meta)
    error = None
    try:
        backend, origin, echo, socks = port(True), port(), port(), port()
        if len({backend, origin, echo, socks}) != 4:
            raise RuntimeError("ephemeral port collision")
        if mode == "native":
            ready = private / "server-ready.json"
            srv = procs.start("server", [frozen["helper"], "server", "-listen", f"127.0.0.1:{backend}",
                              "-cert", identity["cert_file"], "-key", identity["key_file"],
                              "-ech-keys", base / "ech-keys.json", "-ready", ready])
            wait(srv, ready.exists)
        else:
            ack_coalesce = mode.startswith("ack-")
            padding = int(mode.removeprefix("ack-")[1:])
            meta["proxy_policy"] = {"web_padding": padding, "ack_coalesce": ack_coalesce}
            fixture = procs.start("origin", [frozen["pxbench"], "serve", "-http", f"127.0.0.1:{origin}",
                                           "-echo", f"127.0.0.1:{echo}"])
            time.sleep(.04)
            if fixture.poll() is not None:
                raise RuntimeError("fixture exited")
            cfg = json.loads((base / "server.json").read_text())
            cfg.update(http3_listen=f"127.0.0.1:{backend}", web_listen="",
                       token_file=str(base / "token"), cert_file=identity["cert_file"],
                       key_file=identity["key_file"], cover_dir=str(base / "cover"),
                       ech_keys_file=str(base / "ech-keys.json"), web_padding=padding,
                       allow_private_targets=True, rate_mbps=8.)
            # Do not send a new field to historical binaries unless this is an
            # explicitly requested ACK-ablation batch (strict JSON decoding).
            if args.ack_batch:
                cfg["ack_coalesce"] = ack_coalesce
                cfg["recovery_mode"] = "legacy"
            write(private / "server.json", cfg)
            srv = procs.start("server", [frozen["protox"], "server", "-config", private / "server.json"])
            wait(srv, lambda: "HTTP/3 listener ready" in (private / "server.log").read_text())
        ready = private / "relay-ready.json"
        relay = procs.start("relay", [frozen["helper"], "relay", "-target", f"127.0.0.1:{backend}",
                                    "-ready", ready, "-out", private / "packets.jsonl",
                                    "-delay", f"{args.delay_ms}ms", "-up-mbps", "2", "-down-mbps", "8"])
        wait(relay, ready.exists)
        endpoint = json.loads(ready.read_text())["address"]
        if mode != "native":
            cfg = json.loads((base / "client.json").read_text())
            cfg.update(socks_listen=f"127.0.0.1:{socks}", token_file=str(base / "token"),
                       pin_sha256=identity["pin_sha256"], ca_file=identity["ca_file"],
                       experimental_pin_only=False, ech_config_file=str(base / "ech-config.bin"),
                       web_padding=padding, rate_mbps=2.,
                       endpoints=[{"network": "h3", "address": endpoint, "server_name": identity["server_name"]}])
            if args.ack_batch:
                cfg["ack_coalesce"] = ack_coalesce
                cfg["recovery_mode"] = "legacy"
            write(private / "client.json", cfg)
            client = procs.start("client", [frozen["protox"], "client", "-config", private / "client.json"])
            wait(client, lambda: "carrier attached" in (private / "client.log").read_text())
        config = dict(workload, mode="native" if mode == "native" else "proxy", address=endpoint,
                      socks=f"127.0.0.1:{socks}", origin=f"http://127.0.0.1:{origin}",
                      server_name=identity["server_name"], pin=identity["pin_sha256"],
                      ca_file=identity["ca_file"], ech_file=str(base / "ech-config.bin"),
                      output=str(private / "workload.jsonl"))
        write(private / "workload.json", config)
        began = time.monotonic_ns()
        runner = procs.start("workload", [frozen["helper"], "client", "-config", private / "workload.json"])
        meta["workload_process_begin_ns"] = began - epoch
        rc = runner.wait(timeout=args.duration + 8)
        meta["workload_exit"] = rc
        if rc:
            raise RuntimeError("workload exited with nonzero status; private log retained")
        # Allow a bounded close/drain interval; its bytes are counted separately
        # from the business-only classifier window.
        time.sleep(.1)
        meta["status"] = "completed"
    except Exception as exc:
        error = type(exc).__name__ + ": " + str(exc)
        meta["status"] = "failed"
        meta["error"] = error
    finally:
        meta["processes"] = procs.close()
        meta["wall_ms"] = (time.monotonic_ns() - epoch) / 1e6
        meta["files"] = {}
        for name in ("packets.jsonl", "workload.jsonl"):
            src = private / name
            if src.exists():
                shutil.copyfile(src, out / name)
                meta["files"][name] = sha(src)
        for role in ("server", "client"):
            path = private / (role + ".log")
            if not path.exists():
                continue
            # Only allow-listed carrier lifecycle facts. No error text, peer
            # address, token, URL, certificate or configuration is published.
            events = []
            for line in path.read_text().splitlines():
                try:
                    v = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if v.get("msg") in ("carrier attached", "carrier detached"):
                    events.append({k: v[k] for k in ("time", "msg", "carrier", "generation", "resumed_flows") if k in v})
            write(out / (role + "-carriers.json"), events)
        write(out / "trial.json", meta)
    print(json.dumps({"id": ident, "status": meta["status"], "wall_ms": meta["wall_ms"]}), flush=True)
    return error is None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--protox", type=Path, required=True)
    p.add_argument("--protox-sha256", required=True, help="reviewed expected binary hash")
    p.add_argument("--proxy-source-commit", default="e4c93d91d228ef6ebb33f1e6fbf112e1805aeff3")
    p.add_argument("--source-manifest", type=Path, help="optional reviewed public source/hash manifest for the frozen binary")
    p.add_argument("--pxbench", type=Path, required=True)
    p.add_argument("--helper", type=Path, required=True)
    p.add_argument("--recognition", type=Path, required=True)
    p.add_argument("--private", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--duration", type=float, default=3.)
    p.add_argument("--train-groups", type=int, default=20)
    p.add_argument("--heldout-groups", type=int, default=12)
    p.add_argument("--delay-ms", type=int, default=20)
    p.add_argument("--modes", default=",".join(MODES), help="comma-separated native and proxy ablations")
    p.add_argument("--seed-base", type=int, default=71700, help="independent workload seed family for a new experiment")
    args = p.parse_args()
    args.modes = tuple(args.modes.split(","))
    if (len(set(args.modes)) != len(args.modes) or args.modes[0] != "native" or "p0" not in args.modes
            or any(m not in SUPPORTED_MODES for m in args.modes)):
        p.error("modes require native first, p0, unique supported labels")
    args.ack_batch = any(m.startswith("ack-") for m in args.modes)
    if sha(args.protox) != args.protox_sha256:
        p.error("protox binary differs from the reviewed expected hash")
    args.private, args.out = args.private.resolve(), args.out.resolve()
    if not args.private.is_relative_to(ROOT / ".local"):
        p.error("private directory must be below repository .local")
    if args.duration < .5 or min(args.train_groups, args.heldout_groups) < 1:
        p.error("positive groups and duration >= .5 required")
    if not 0 <= args.seed_base < 2**64 - args.train_groups - args.heldout_groups:
        p.error("seed family must fit unsigned 64-bit helper seeds")
    args.private.mkdir(mode=0o700, parents=True, exist_ok=False)
    args.out.mkdir(parents=True, exist_ok=False)
    frozen = {}
    for role in ("protox", "pxbench", "helper", "recognition"):
        src = getattr(args, role).resolve()
        dst = args.private / role
        shutil.copyfile(src, dst)
        dst.chmod(0o700)
        frozen[role] = dst
    manifest = {"schema": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
                "binaries_sha256": {k: sha(v) for k, v in frozen.items()},
                "proxy_source_commit": args.proxy_source_commit,
                "proxy_source_identity": "verified input binary hash; source relationship supplied and audited separately",
                "duration_seconds": args.duration, "train_groups": args.train_groups,
                "heldout_groups": args.heldout_groups,
                "modes": args.modes, "seed_base": args.seed_base,
                "paired_group_fields": "seed, workload, all modes; no fragments cross split",
                "capture": "actual UDP ingress metadata at controlled relay; no payload retained",
                "network": "loopback sockets with per-direction serialization at 8/2 Mbps including IPv4+UDP headers, propagation delay",
                "limitations": ["native reference is a scripted Go H3 application, not a browser population",
                                "fixed per-run private CA, names and capture tool are identical for all labels and excluded from features",
                                "cost includes handshake, health and closure; classifier uses business-only window",
                                "post-2026-11-07 real network/DPI or production access is not part of this experiment"]}
    write(args.out / "manifest.json", manifest)
    if args.source_manifest:
        source_manifest = json.loads(args.source_manifest.read_text())
        if source_manifest.get("binary_sha256") != sha(args.protox):
            p.error("source manifest identifies a different binary")
        write(args.out / "source-manifest.json", {k: source_manifest[k] for k in
              ("utc", "baseline_commit", "sources_sha256", "binary_sha256", "build") if k in source_manifest})
    write(args.out / "analysis-preregistration.json", {
        "frozen_utc": datetime.now(timezone.utc).isoformat(),
        "files": {str(path.relative_to(ROOT)): sha(path) for path in
                  (ROOT / "tools/shapebench" / name for name in ("analyze.py", "audit.py", "main.go", "run.py"))},
        "model": "L2=1 logistic, full/length-only/timing-counts-only; frozen p0 and retrain per proxy mode",
        "selection": "whole matched seed group; train groups then untouched heldout groups",
        "threshold": "strictly greater than maximum native training score; not a guaranteed low-FPR operating point",
        "modes": args.modes, "seed_base": args.seed_base,
        "note": "automatically written before identity generation and before any trial; earlier batches are exploratory evidence for this batch",
    })
    base = args.private / "config"
    subprocess.run([str(frozen["protox"]), "init", "-dir", str(base), "-host", "127.0.0.1", "-server-name", "unused-shape.example.test"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
    certs = args.private / "identity"
    subprocess.run([str(frozen["recognition"]), "cert", "-out", str(certs)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
    identity = json.loads((certs / "identity.json").read_text())
    subprocess.run([str(frozen["protox"]), "ech-keygen", "-dir", str(base), "-public-name", identity["ech_public_name"]],
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
    failures = 0
    for group in range(args.train_groups + args.heldout_groups):
        modes = list(args.modes)
        random.Random(90111 + group).shuffle(modes)
        for order, mode in enumerate(modes):
            failures += not one(args, frozen, base, identity, group, mode, order)
    write(args.out / "completion.json", {"trials": (args.train_groups + args.heldout_groups) * len(args.modes),
                                         "failed_trials": failures, "completed_utc": datetime.now(timezone.utc).isoformat()})


if __name__ == "__main__":
    main()
