#!/usr/bin/env python3
"""Stage a frozen baseline/candidate pair in the task-private Linux VM."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[2]
VMROOT = "/tmp/pxlab-v03"


def call(argv, **kwargs):
    return subprocess.run([str(x) for x in argv], check=True, cwd=ROOT, **kwargs)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--baseline", type=Path, required=True, help="frozen Linux arm64 binary")
    ap.add_argument("--candidate", type=Path, required=True, help="Linux arm64 candidate")
    ap.add_argument("--generator", type=Path, default=ROOT/".local/v03/baseline/protox")
    ap.add_argument("--bench", type=Path, default=ROOT/".local/v03/baseline/pxbench-linux-arm64")
    ap.add_argument("--fixture", type=Path, required=True, help="Linux arm64 recoverybench with instrumented origin")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("matrix_args", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    if not a.run_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for c in a.run_id):
        ap.error("unsafe run-id")
    if (ROOT/"results"/a.run_id).exists():
        ap.error("refusing to overwrite existing results")
    stage = ROOT/".local/v03"/("netstage-"+a.run_id)
    px = stage/"private/px"
    px.mkdir(parents=True, mode=0o700, exist_ok=True)
    bindir = stage/"bin"
    bindir.mkdir(exist_ok=True)
    logs = ROOT/".local/v03/stage.log"
    with logs.open("a") as log:
        if not (px/"client.json").exists():
            call([a.generator, "init", "-dir", px, "-host", "10.203.0.2", "-server-name", "notes.protox.test",
                  "-tls-port", "14443", "-quic-port", "14443"], stdout=log, stderr=log)
            call([a.generator, "ech-keygen", "-dir", px, "-public-name", "cover.protox.test"], stdout=log, stderr=log)
            call(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                  "-nodes", "-days", "30", "-subj", "/CN=notes.protox.test",
                  "-addext", "subjectAltName=DNS:notes.protox.test,DNS:cover.protox.test",
                  "-addext", "basicConstraints=critical,CA:TRUE",
                  "-keyout", px/"server.key", "-out", px/"server.crt"], stdout=log, stderr=log)
        call(["python3", "scripts/baselines/configure.py", "--server", "10.203.0.2", "--out", stage/"private/baseline",
              "--server-directory", VMROOT+"/private/baseline", "--reality-target", "127.0.0.1:39443",
              "--reality-sni", "protox-baseline.test", "--allow-test-cidr", "127.0.0.1/32"], stdout=log, stderr=log)
    der = subprocess.check_output(["openssl", "x509", "-in", str(px/"server.crt"), "-outform", "DER"])
    for side in ("server", "client"):
        base = json.loads((px/f"{side}.json").read_text())
        base.update(rate_mbps=8 if side == "server" else 2, allow_private_targets=side == "server", test_rotate_seconds=0)
        base["web_padding"] = 127
        if side == "server":
            base["ech_keys_file"] = "ech-keys.json"
        else:
            base.update(ech_config_file="ech-config.bin", ca_file="server.crt", experimental_pin_only=False,
                        pin_sha256=hashlib.sha256(der).hexdigest())
        for variant in ("v02", "fixed", "adaptive", "no-prepare", "age", "count", "age-no-prepare", "causal", "probe-only", "joint"):
            config = copy.deepcopy(base)
            if variant != "v02":
                config.update(recovery_mode="legacy" if variant == "fixed" else "adaptive", recovery_trace=True)
                if variant in ("no-prepare", "age-no-prepare"):
                    config["recovery_no_prepare"] = True
                if variant in ("age", "count", "age-no-prepare"):
                    config["recovery_count_history"] = variant == "count"
                if variant in ("causal", "probe-only", "joint"):
                    config.update(recovery_count_history=True, recovery_probe_only=variant == "probe-only")
                if variant == "joint":
                    config.update(web_padding=0, ack_coalesce=True)
                if variant == "fixed":
                    config.update(heartbeat_ms=100, dead_ms=400)
            (px/f"{side}-{variant}.json").write_text(json.dumps(config, indent=2)+"\n")
    for path in (stage/"private/baseline").glob("hysteria-client-*.json"):
        config = json.loads(path.read_text())
        config["tls"]["ca"] = VMROOT+"/private/baseline/tls-cert.pem"
        path.write_text(json.dumps(config, indent=2)+"\n")
    for p in (stage/"private").rglob("*"):
        p.chmod(0o700 if p.is_dir() else 0o600)
    for src, dst in ((a.baseline, "protox-v02"), (a.candidate, "protox-candidate"), (a.bench, "pxbench"), (a.fixture, "recoverybench")):
        shutil.copy2(src.resolve(), bindir/dst)
    for name in ("xray", "hysteria", "tlscover"):
        shutil.copy2(ROOT/".local/baselines/bin/linux-arm64"/name, bindir/name)
    for name in ("matrix.py", "netlab.py", "v03_matrix.py"):
        shutil.copy2(ROOT/"tools/lab"/name, stage/name)
    parameters = dict(link="tc netem with actual IP packets, 8/2Mbps unless profile states otherwise",
                      proxy=dict(baseline="v0.2 frozen", candidate="hash in manifest", padding=dict(default=127, joint=0), ech_required=True,
                                 normal_CA_hostname_and_pin_validation=True, server_rate_mbps=8, client_rate_mbps=2),
                      variants=dict(v02="500/2000ms legacy", fixed="100/400ms legacy; manager100ms retained",
                                    adaptive="RTT/probe evidence, prepare before commit", no_prepare="same detector; cold dial after drop",
                                    age="same candidate, time-aged RTT history", count="same candidate, count-only RTT history ablation",
                                    age_no_prepare="time-aged RTT history, cold dial after drop",
                                    causal="count RTT history + causal DATA/OPEN roundtrip proof", probe_only="same candidate, matched PONG evidence only",
                                    joint="count/causal recovery + ACK coalescing + padding0; bundle comparison only"),
                      reference=dict(xray="26.10.31 REALITY+Vision, actual owned TLS target, HTTPS workload",
                                     hysteria="2.13.0 BBR standard, no H2 standby"),
                      scope="fresh private CA in a synthetic network, no browser or field-DPI equivalence")
    safe_keys=("rate_mbps", "heartbeat_ms", "dead_ms", "web_padding", "priority", "adaptive", "window_bytes",
               "max_flows", "max_sessions", "resume_seconds", "dial_timeout_ms", "test_rotate_seconds",
               "recovery_mode", "recovery_count_history", "recovery_probe_only", "recovery_no_prepare", "ack_coalesce")
    parameters["per_config_parameters"]={p.name:{k:v for k,v in json.loads(p.read_text()).items() if k in safe_keys}
                                          for p in sorted(px.glob("*-*.json")) if p.name.startswith(("client-", "server-"))}
    (stage/"public-parameters.json").write_text(json.dumps(parameters, indent=2)+"\n")
    archive = ROOT/".local/v03"/("netstage-"+a.run_id+".tar.gz")
    with tarfile.open(archive, "w:gz") as tar:
        for p in stage.iterdir():
            tar.add(p, arcname=p.name)
    vm = ["scripts/lab/vm.sh"]
    call(vm+["copy", archive, "protox-lab:/tmp/pxlab-v03-stage.tar.gz"])
    call(vm+["shell", "sudo", "mkdir", "-p", VMROOT])
    call(vm+["shell", "sudo", "tar", "-xzf", "/tmp/pxlab-v03-stage.tar.gz", "-C", VMROOT])
    args = a.matrix_args[1:] if a.matrix_args[:1] == ["--"] else a.matrix_args
    result = subprocess.run(vm+["shell", "sudo", "python3", VMROOT+"/v03_matrix.py", "--root", VMROOT,
                                "--run-id", a.run_id]+args, cwd=ROOT)
    # Retrieve completed and failed trials alike, even after a runner error.
    call(vm+["shell", "sudo", "chmod", "-R", "a+rX", VMROOT+"/results/"+a.run_id])
    call(vm+["copy", "-r", "protox-lab:"+VMROOT+"/results/"+a.run_id, ROOT/"results"/a.run_id])
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
