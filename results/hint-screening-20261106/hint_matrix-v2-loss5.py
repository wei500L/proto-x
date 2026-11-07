#!/usr/bin/env python3
"""Sparse-copy on/off ablation with a single binary and retained activity logs."""
import argparse
import json
import os
from pathlib import Path
import signal
import sys

from matrix import Matrix, PROFILES, sha, write
from cc_matrix import sanitized


# Declared after the initial 1% studies, before seed317; original results stay.
PROFILES["loss5-jitter5"] = {"rtt": 60, "jitter": 5, "loss": 5, "up": 2, "down": 8}
VARIANTS = ["px-hints-off", "px-hints-on", "hy-brutal6"]


class HintMatrix(Matrix):
    def one(self, index, variant, profile, seed):
        trial = super().one(index, variant, profile, seed)
        directory = self.out / trial["trial_id"]
        trial["protocol_binary"] = "protox" if variant.startswith("px-") else "hysteria"
        if variant.startswith("px-"):
            trial["congestion_control"] = "quic-go v0.65.0 default Reno"
            trial["sparse_redundancy"] = variant == "px-hints-on"
            activity = {"scope": "session lifetime includes startup, warmup, measurement and shutdown",
                        "sent_semantics": "successful QUIC datagram submission, not proof of wire transmission",
                        "delivery_semantics": "copy delivered bytes first, not proof the original was lost",
                        "records_are_not_summed": "counter records lack session identity and may be repeated",
                        "roles": {}}
            quic_only = True
            for role in ("server", "client"):
                path = directory / f"{role}.log"
                events = []
                for line in (path.read_text() if path.exists() else "").splitlines():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                carriers = [e.get("carrier") for e in events if e.get("msg") == "carrier attached"]
                quic_only = quic_only and bool(carriers) and all(x == "quic" for x in carriers)
                records = [e for e in events if e.get("msg") == "sparse redundancy counters"]
                activity["roles"][role] = {"carrier_attachments": carriers, "counter_records": records,
                    "last_record": records[-1] if records else None,
                    "sent_activity_observed": any(e.get("sent_datagrams", 0) > 0 for e in records),
                    "copy_first_delivery_observed": any(e.get("first_delivered_bytes", 0) > 0 for e in records),
                    "missing_counter_log": not records}
            trial["hint_activity"] = activity
            trial["quic_only_validated"] = quic_only
            if trial["status"] == "completed" and not quic_only:
                trial["status"] = "carrier_validation_failed"
        write(directory / "trial.json", trial)
        write(self.out / "index.json", self.rows)
        print(json.dumps({"checked_trial": trial["trial_id"], "final_status": trial["status"],
                          "hint_activity": trial.get("hint_activity")}), flush=True)
        return trial

    def execute(self):
        configs = self.out / "sanitized-configs"
        configs.mkdir()
        hashes = {}
        for source in sorted(self.private.rglob("*.json")):
            relative = source.relative_to(self.private)
            dest = configs / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            write(dest, sanitized(json.loads(source.read_text())))
            hashes[str(relative)] = sha(source)
        code = super().execute()
        path = self.out / "manifest.json"
        metadata = json.loads(path.read_text())
        metadata["hint_experiment_script_sha256"] = sha(Path(__file__))
        metadata["redactor_module_sha256"] = sha(self.root / "cc_matrix.py")
        metadata["private_config_sha256"] = hashes
        metadata["hint_provenance"] = json.loads((self.root / "hint-provenance.json").read_text())
        metadata["notes"] += [
            "On/off uses the same sparse-copy binary. Both endpoints explicitly set sparse_redundancy to the selected mode.",
            "Both PX modes use default Reno, window64KiB, priority=true, adaptive=false and the same8/2Mbps app pacer.",
            "Copy datagrams may win because of scheduling or packaging; first-delivered counters do not prove loss recovery.",
            "Successful datagram submission can precede actual transmission. Missing shutdown counters are recorded as missing, not zero activity.",
            "Counter logs include startup/warmup; their values are not measurement-window wire-overhead accounting."]
        write(path, metadata)
        return code


def main():
    def interrupt(signum, frame):
        raise KeyboardInterrupt(f"hint matrix interrupted by signal {signum}")
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupt)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="/tmp/pxlab-hints")
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
        parser.error("seed307 remains reserved for independent confirmation")
    if os.geteuid() != 0:
        parser.error("run as root only inside the dedicated lab VM")
    if not args.run_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for c in args.run_id):
        parser.error("unsafe run-id")
    return HintMatrix(args).execute()


if __name__ == "__main__":
    sys.exit(main())
