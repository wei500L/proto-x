#!/usr/bin/env python3
"""Isolated CC screening on the existing packet-level lab, with log validation."""
import argparse
import json
import os
from pathlib import Path
import signal
import sys
import time

from matrix import Matrix, PROFILES, sha, write


MODES = {"px-fork-reno": "reno", "px-fork-bbr-standard": "hy-bbr-standard",
         "px-fork-brutal6": "hy-brutal"}
VARIANTS = ["px-priority", *MODES, "hy-brutal6"]
SOURCE = "ca8fbd874fd6ca82413948de6dc5924405e103e1"


def sanitized(value, key=""):
    if key.lower() in {"auth", "password", "token", "id", "privatekey", "publickey", "shortids",
                       "shortid", "pin_sha256", "vless_id", "reality_private", "reality_public",
                       "reality_short_id", "hysteria_auth"}:
        return "<redacted>"
    if isinstance(value, dict):
        return {k: sanitized(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitized(x) for x in value]
    return value


class CCMatrix(Matrix):
    def services(self, variant, procs):
        if variant not in MODES:
            return super().services(variant, procs)
        baseline = self.private / "baseline"
        procs.start("fixture", "server", [self.bin / "pxbench", "serve", "-http", "",
                    "-https", "127.0.0.1:18443", "-echo", "127.0.0.1:18081",
                    "-cert", baseline / "tls-cert.pem", "-key", baseline / "tls-key.pem"])
        for side in ("server", "client"):
            env = ["env", "PROTOX_CC=" + MODES[variant], "PROTOX_CC_DISABLE_LOSS_COMPENSATION=false"]
            if MODES[variant] == "hy-brutal":
                env += ["PROTOX_CC_BRUTAL_MBPS=" + ("6" if side == "server" else "1.5")]
            procs.start(side, side, env + [self.bin / "protox-cc", side, "-config",
                        self.private / "px" / f"{side}-px-priority.json"])
            if side == "server":
                time.sleep(0.15)
        return 1088

    def one(self, index, variant, profile, seed):
        trial = super().one(index, variant, profile, seed)
        directory = self.out / trial["trial_id"]
        if variant.startswith("px-"):
            fork = variant in MODES
            trial["protocol_binary"] = "protox-cc" if fork else "protox"
            trial["congestion_control"] = MODES[variant] if fork else "quic-go v0.65.0 default Reno"
            validation = {"required_controller": MODES.get(variant), "roles": {}, "passed": True}
            for role in ("server", "client"):
                events = []
                log_path = directory / f"{role}.log"
                for line in (log_path.read_text() if log_path.exists() else "").splitlines():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                installed = [e for e in events if e.get("msg") == "experimental QUIC controller installed"]
                attached = [e.get("carrier") for e in events if e.get("msg") == "carrier attached"]
                valid = bool(attached) and all(x == "quic" for x in attached)
                expected_rate = (750000 if role == "server" else 187500) if MODES.get(variant) == "hy-brutal" else 0
                if fork:
                    valid = valid and bool(installed) and all(
                        e.get("controller") == MODES[variant] and e.get("hysteria_source") == SOURCE and
                        e.get("brutal_bytes_per_second") == expected_rate and e.get("disable_loss_compensation") is False
                        for e in installed)
                validation["roles"][role] = {"passed": valid, "carrier_attachments": attached,
                                              "installation_records": installed}
                validation["passed"] = validation["passed"] and valid
            trial["controller_validation"] = validation
            if trial["status"] == "completed" and not validation["passed"]:
                trial["status"] = "controller_validation_failed"
        else:
            trial["protocol_binary"] = "hysteria"
            trial["congestion_control"] = "Hysteria 2.13.0 Brutal 6/1.5 Mbps"
        write(directory / "trial.json", trial)
        write(self.out / "index.json", self.rows)
        print(json.dumps({"checked_trial": trial["trial_id"], "final_status": trial["status"],
                          "controller_validation": trial.get("controller_validation")}), flush=True)
        return trial

    def execute(self):
        configs = self.out / "sanitized-configs"
        configs.mkdir()
        config_hashes = {}
        for source in sorted(self.private.rglob("*.json")):
            relative = source.relative_to(self.private)
            dest = configs / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            write(dest, sanitized(json.loads(source.read_text())))
            config_hashes[str(relative)] = sha(source)
        code = super().execute()
        path = self.out / "manifest.json"
        metadata = json.loads(path.read_text())
        metadata["cc_experiment_script_sha256"] = sha(Path(__file__))
        metadata["private_config_sha256"] = config_hashes
        metadata["cc_provenance"] = json.loads((self.root / "cc-provenance.json").read_text())
        metadata["notes"] += [
            "This is a separate CC screening batch after the common-source pacing and scheduler ablations.",
            "Stable PX is upstream quic-go v0.65.0 Reno; fork Reno controls for the older Hy QUIC fork and explicit QUIC v1.",
            "Compare fork Reno/BBR/Brutal to isolate controller changes; stable-vs-fork changes are not solely CC gains.",
            "No rebinding or recovery is injected here. The experimental fork can reset its controller to Reno on path migration.",
            "Every PX trial validates QUIC attachments; experimental trials also validate both endpoints' actual post-auth controller logs."]
        write(path, metadata)
        return code


def main():
    def interrupt(signum, frame):
        raise KeyboardInterrupt(f"CC matrix interrupted by signal {signum}")
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupt)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="/tmp/pxlab-cc")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--stage", choices=["discovery"], default="discovery")
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument("--duration", type=float, default=25)
    parser.add_argument("--warmup", type=float, default=3)
    parser.add_argument("--queue-ms", type=float, default=100)
    parser.add_argument("--background", type=int, default=1)
    parser.add_argument("--background-mbps", type=float)
    parser.add_argument("--variants", nargs="+", choices=VARIANTS, default=VARIANTS)
    parser.add_argument("--profiles", nargs="+", choices=list(PROFILES), default=["loss1-jitter5"])
    args = parser.parse_args()
    if args.seed == 307:
        parser.error("seed307 is reserved for independent confirmation and is not allowed in this screening runner")
    if os.geteuid() != 0:
        parser.error("run as root only inside the dedicated lab VM")
    if not args.run_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for c in args.run_id):
        parser.error("unsafe run-id")
    return CCMatrix(args).execute()


if __name__ == "__main__":
    sys.exit(main())
