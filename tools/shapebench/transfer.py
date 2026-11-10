#!/usr/bin/env python3
"""Post-hoc cross-batch check of the original p0 detector, without refitting on target data."""
import argparse
import json
from pathlib import Path

import analyze


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("target", type=Path)
    args = parser.parse_args()
    data = []
    for path in sorted(args.source.glob("*/trial.json")):
        row = analyze.extract(path.parent)
        if row["split"] == "train":
            row["group"] = "source-" + str(row["group"])
            data.append(row)
    for path in sorted(args.target.glob("*/trial.json")):
        row = analyze.extract(path.parent)
        row["group"] = "target-" + str(row["group"])
        row["split"] = "heldout"
        data.append(row)
    names = list(data[0]["features"])
    sets = {"full": names, "size_only": [n for n in names if "size_" in n],
            "timing_counts_only": [n for n in names if "size_" not in n and "bytes_per_second" not in n]}
    modes = json.loads((args.target / "manifest.json").read_text())["modes"][1:]
    result = {
        "schema": 1, "source_batch": args.source.name, "target_batch": args.target.name,
        "kind": "post-hoc diagnostic: source training groups only; fixed p0 model and native-training threshold; target used only for evaluation",
        "target_scope": "all target groups, including groups used to fit the separate within-target experiment; no target sample is used for this transfer fit",
        "detectors": {family: [analyze.detector_result(data, mode, selected, "p0") for mode in modes]
                      for family, selected in sets.items()},
        "limitation": "different collection dates and workload seeds on the same host/emulator/Go implementation family; not cross-network or independent-site generalization",
    }
    (args.target / "cross-date-transfer.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    for family, results in result["detectors"].items():
        print(json.dumps({"family": family, "results": [{k: x[k] for k in ("tested_proxy_mode", "auc", "true_positives", "positives", "false_positives", "negatives")} for x in results]}))


if __name__ == "__main__":
    main()
