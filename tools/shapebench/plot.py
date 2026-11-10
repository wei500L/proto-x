#!/usr/bin/env python3
"""Plot descriptive padding cost/detection/latency tradeoffs, without refitting."""
import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    analysis = json.loads((args.directory / "analysis.json").read_text())
    audit = json.loads((args.directory / "audit.json").read_text())
    manifest = json.loads((args.directory / "manifest.json").read_text())
    first_trial = json.loads(next(args.directory.glob("*/trial.json")).read_text())
    rtt_ms = 2 * first_trial["relay"]["one_way_delay_ms"]
    modes = sorted(manifest["modes"][1:], key=lambda m: analysis["metrics"][m]["median_paired_extra_carrier_fraction_vs_p0"])
    cost = [analysis["metrics"][m]["median_paired_extra_carrier_fraction_vs_p0"] * 100 for m in modes]
    detectors = analysis["detectors"]["full"]["retrained_each_mode"]
    auc = [next(x["auc"] for x in detectors if x["tested_proxy_mode"] == m) for m in modes]
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
    fig, (left, right) = plt.subplots(1, 2, figsize=(10.5, 4.2), constrained_layout=True)
    left.plot(cost, auc, marker="o", color="#A64534")
    for x, y, mode in zip(cost, auc, modes):
        left.annotate(mode, (x, y), xytext=(0, -18), textcoords="offset points", ha="center")
    left.set_ylim(0, 1.05)
    left.set_title("Held-out proxy-vs-native Go H3 detection")
    left.set_ylabel("AUC (lower = harder to distinguish)")
    right.plot(cost, [analysis["metrics"][m]["http_latency_ms"]["p99"] for m in modes],
               marker="o", color="#A64534", label="All successful HTTP requests")
    right.plot(cost, [audit["modes"][m]["later_http_success_latency_ms"]["p99"] for m in modes],
               marker="s", color="#225C67", label="Excluding first request per session")
    right.set_ylim(0, 115)
    right.set_title("Observed HTTP p99; startup stays in main result")
    right.set_ylabel("Latency (ms)")
    right.legend(loc="lower right", fontsize=8)
    for ax in (left, right):
        ax.set_xlabel("Median extra UDP bytes per received byte vs p0 (%)")
        ax.grid(alpha=.2)
    fig.suptitle(f"{audit['complete_groups']} paired groups × {len(manifest['modes'])} modes × "
                 f"{manifest['duration_seconds']:g} seconds; {rtt_ms:g} ms emulated RTT, 8/2 Mbps\n"
                 f"{manifest['heldout_groups']} held-out groups/class; this experiment does not establish real-DPI behavior", fontsize=11)
    fig.savefig(args.directory / "tradeoff.svg", metadata={"Date": None})
    fig.savefig(args.directory / "tradeoff.png", dpi=160)


if __name__ == "__main__":
    main()
