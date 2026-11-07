#!/usr/bin/env python3
"""Compare declared, redacted observations; this does not train a classifier."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


ACTIVE_FIELDS = (
    "case", "method", "authentication_class", "status", "error", "body_error",
    "http_status", "http_protocol", "headers", "content_length",
    "negotiated_alpn", "tls_version", "certificate_chain_verified",
    "body_bytes_observed", "body_truncated_at_bound", "body_sha256",
    "offered_alpn", "payload_class", "legacy_record_bytes", "response_bytes",
    "response_sha256", "response_truncated_at_bound", "read_error",
    "process_exit_code", "certificate_verification_reported", "visitor_profile", "tls_client_stack",
)
TIME_FIELDS = ("headers_elapsed_ms", "handshake_elapsed_ms", "complete_elapsed_ms")


def read_report(path):
    data = path.read_bytes()
    report = json.loads(data)
    if report.get("schema") != 1 or not isinstance(report.get("observations"), list):
        raise ValueError("input is not a supported redacted observation report")
    return report, hashlib.sha256(data).hexdigest()


def index_rows(rows):
    indexed = {}
    for row in rows:
        key = (row.get("repeat"), row.get("case"))
        if key[0] is None or key[1] is None or key in indexed:
            raise ValueError("missing or duplicate active probe case/repeat; refusing to discard a sample")
        indexed[key] = row
    return indexed


def compare_active(candidate, reference):
    a = index_rows(candidate["observations"])
    b = index_rows(reference["observations"])
    if candidate.get("network") != reference.get("network"):
        raise ValueError("active probe networks differ")
    pairs = []
    for key in sorted(set(a) | set(b)):
        x, y = a.get(key), b.get(key)
        item = {"repeat": key[0], "case": key[1]}
        if x is None or y is None:
            item.update(status="missing_pair", candidate_present=x is not None, reference_present=y is not None)
        else:
            # Missing and explicit null are different observations.
            diffs = []
            for field in ACTIVE_FIELDS:
                xv, yv = x.get(field), y.get(field)
                if (field in x) != (field in y) or xv != yv:
                    diffs.append({"field": field, "candidate_present": field in x,
                                  "reference_present": field in y, "candidate": xv, "reference": yv})
            item.update(status="normalized_match" if not diffs else "different", differences=diffs,
                        candidate_status=x.get("status"), reference_status=y.get("status"),
                        candidate_times={f: x[f] for f in TIME_FIELDS if f in x},
                        reference_times={f: y[f] for f in TIME_FIELDS if f in y})
        pairs.append(item)
    counts = Counter(x["status"] for x in pairs)
    return {
        "mode": "active", "network": candidate.get("network"),
        "candidate_attempts": len(a), "reference_attempts": len(b),
        "candidate_status_counts": dict(Counter(x.get("status") for x in a.values())),
        "reference_status_counts": dict(Counter(x.get("status") for x in b.values())),
        "pair_status_counts": dict(counts), "pairs": pairs,
        "comparison_fields": list(ACTIVE_FIELDS),
        "timing_samples_retained_but_not_used_for_response_match": True,
        "limitations": [
            "A normalized match can include two rejected or failed requests. Status counts and every pair remain visible.",
            "Only declared status/protocol/header/body/error fields are compared. Date and private header values are outside this comparison.",
            "Different listeners and executions add timing variance; these samples do not prove timing indistinguishability.",
            "This comparison does not test authenticated proxy interoperability, arbitrary active probes, real-world DPI, or Russian reachability.",
            "A same-stack ordinary control isolates the effect of the candidate's HTTP gate; it is not a diverse cover-traffic corpus.",
        ],
    }


def hello_distribution(report):
    features = {}
    counts = Counter()
    errors = []
    for row in report["observations"]:
        if row.get("status") != "client_hello_decoded":
            errors.append({"flow": row.get("flow"), "status": row.get("status"), "reason": row.get("reason")})
            continue
        feature = {"transport": row["transport"], "client_hello": row["client_hello"]}
        if "quic_version" in row:
            feature["quic_version"] = row["quic_version"]
        encoded = json.dumps(feature, sort_keys=True, separators=(",", ":")).encode()
        fingerprint = hashlib.sha256(encoded).hexdigest()
        counts[fingerprint] += 1
        features[fingerprint] = feature
    return counts, features, errors


def compare_hello(candidate, reference):
    ac, af, ae = hello_distribution(candidate)
    bc, bf, be = hello_distribution(reference)
    features = {**af, **bf}
    rows = [{"redacted_feature_sha256": key, "candidate_count": ac[key], "reference_count": bc[key],
             "features": features[key]} for key in sorted(features)]
    rule = lambda report: sum(bool(x.get("client_hello", {}).get("legacy_custom_alpn_observed"))
                              for x in report["observations"])
    return {
        "mode": "hello", "candidate_decoded": sum(ac.values()), "reference_decoded": sum(bc.values()),
        "candidate_undecoded": ae, "reference_undecoded": be,
        "candidate_legacy_alpn_rule_matches": rule(candidate), "reference_legacy_alpn_rule_matches": rule(reference),
        "exact_redacted_feature_histograms_equal": ac == bc,
        "feature_distributions": rows,
        "limitations": [
            "These are exact histograms of the retained structural features, not a trained or held-out traffic classifier.",
            "Randomized extension/transport-parameter order, offered options and sample counts can change these histograms.",
            "A missing custom-ALPN match demonstrates only the outcome of that rule for decoded observations.",
            "Keep native-client captures separate from legacy active probes, which deliberately offer the legacy ALPN.",
            "SNI values are redacted. ECH presence alone cannot establish ECH acceptance or conceal traffic purpose.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--mode", choices=("active", "hello"), default="active")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("refusing to overwrite an existing comparison")
    candidate, candidate_sha = read_report(args.candidate)
    reference, reference_sha = read_report(args.reference)
    result = (compare_active if args.mode == "active" else compare_hello)(candidate, reference)
    result.update(schema=1, created_utc=datetime.now(timezone.utc).isoformat(),
                  candidate_label=candidate.get("label"), reference_label=reference.get("label"),
                  candidate_report_sha256=candidate_sha, reference_report_sha256=reference_sha)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"report": str(args.out), "mode": args.mode,
                      "pair_status_counts": result.get("pair_status_counts")}))


if __name__ == "__main__":
    main()
