#!/usr/bin/env python3
"""Check the validator using in-memory corruptions of an existing real trial.

The fixture files are never modified. These are negative validation controls,
not additional protocol measurements.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
from unittest import mock

import summarize


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trial", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    read_json, read_events = summarize.read_json, summarize.read_events
    files_before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in args.trial.iterdir() if p.is_file()}
    cases = []

    def run(name, modify_json=None, modify_events=None, expect=None):
        def json_reader(path):
            value = copy.deepcopy(read_json(path))
            if modify_json:
                modify_json(path.name, value)
            return value

        def event_reader(path):
            value = copy.deepcopy(read_events(path))
            return modify_events(path.name, value) if modify_events else value

        with mock.patch.object(summarize, "read_json", side_effect=json_reader), mock.patch.object(summarize, "read_events", side_effect=event_reader):
            errors = summarize.analyze(args.trial)["validation_errors"]
        passed = not errors if expect is None else any(expect in error for error in errors)
        cases.append({"case": name, "passed": passed, "observed_errors": errors, "expected_error_substring": expect})

    def summary_change(fn):
        return lambda name, value: fn(value) if name == "events.summary.json" else None

    run("unaltered_real_fixture")
    run("wrong_http_success_count", summary_change(lambda v: v["operations"]["http"].__setitem__("success", 0)), expect="http success count differs")
    run("wrong_http_p99", summary_change(lambda v: v["operations"]["http"]["successful_latency_ms"].__setitem__("p99", 1000000)), expect="http.latency_ms.p99")
    run("wrong_download_bytes", summary_change(lambda v: v.__setitem__("download_validated_bytes", 0)), expect="download byte population differs")
    run("wrong_sse_token_count", summary_change(lambda v: v["sse"].__setitem__("tokens", 0)), expect="SSE tokens differs")
    run("missing_censored_download", modify_events=lambda n, v: [x for x in v if x["kind"] != "download_end"] if n == "events.jsonl" else v,
        expect="download_end total differs")
    run("missing_relay_stop", modify_events=lambda n, v: [x for x in v if x["kind"] != "capture_stopped"] if n == "relay-events.jsonl" else v,
        expect="relay capture missing unique start/stop")

    def change_rss(name, values):
        if name == "resources.jsonl":
            for value in values:
                if value.get("role") == "client":
                    value["rss_kib"] = 1000000000
                    break
        return values

    run("wrong_resource_peak", modify_events=change_rss, expect="client RSS summary differs")
    files_after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in args.trial.iterdir() if p.is_file()}
    result = {"scope": "synthetic in-memory negative controls for validator; not protocol measurements",
              "fixture": args.trial.as_posix(), "fixture_file_sha256": files_before,
              "fixture_unchanged": files_before == files_after,
              "validator_sha256": hashlib.sha256(Path(summarize.__file__).read_bytes()).hexdigest(),
              "selfcheck_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "cases": cases}
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    passed = all(c["passed"] for c in cases) and result["fixture_unchanged"]
    print(json.dumps({"passed": passed, "cases": len(cases), "fixture_unchanged": result["fixture_unchanged"]}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
