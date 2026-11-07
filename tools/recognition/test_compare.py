"""Ensure observation failures and missing pairs cannot become clean matches."""
import unittest

from compare import compare_active, compare_hello


def report(rows):
    return {"schema": 1, "network": "h2", "observations": rows}


class ComparisonChecks(unittest.TestCase):
    def test_both_failed_are_retained_as_failures_even_if_matching(self):
        row = {"case": "root_get", "repeat": 0, "status": "request_failed",
               "error": {"timeout": True}, "headers_elapsed_ms": 1000}
        value = compare_active(report([row]), report([dict(row, headers_elapsed_ms=2000)]))
        self.assertEqual(value["pair_status_counts"], {"normalized_match": 1})
        self.assertEqual(value["candidate_status_counts"], {"request_failed": 1})
        self.assertEqual(value["pairs"][0]["reference_status"], "request_failed")
        self.assertEqual(value["pairs"][0]["reference_times"]["headers_elapsed_ms"], 2000)

    def test_missing_repeat_is_not_discarded(self):
        row = {"case": "root_get", "repeat": 0, "status": "response_observed"}
        value = compare_active(report([row, dict(row, repeat=1)]), report([row]))
        self.assertEqual(value["pair_status_counts"], {"normalized_match": 1, "missing_pair": 1})
        self.assertEqual(value["candidate_attempts"], 2)
        self.assertEqual(value["reference_attempts"], 1)

    def test_duplicate_repeat_is_rejected(self):
        row = {"case": "root_get", "repeat": 0, "status": "response_observed"}
        with self.assertRaisesRegex(ValueError, "duplicate"):
            compare_active(report([row, row]), report([row]))

    def test_changed_body_and_missing_field_are_visible(self):
        a = {"case": "root_get", "repeat": 0, "status": "response_observed", "body_sha256": "A", "error": None}
        b = {"case": "root_get", "repeat": 0, "status": "response_observed", "body_sha256": "B"}
        value = compare_active(report([a]), report([b]))
        self.assertEqual(value["pair_status_counts"], {"different": 1})
        self.assertEqual({x["field"] for x in value["pairs"][0]["differences"]}, {"body_sha256", "error"})

    def test_hello_denominators_include_undecoded(self):
        a = report([{"status": "not_decoded", "flow": "udp-1", "reason": "truncated"}])
        b = report([{"status": "client_hello_decoded", "transport": "quic_initial",
                     "quic_version": "0x00000001", "client_hello": {"legacy_custom_alpn_observed": True}}])
        value = compare_hello(a, b)
        self.assertEqual(value["candidate_decoded"], 0)
        self.assertEqual(len(value["candidate_undecoded"]), 1)
        self.assertEqual(value["reference_legacy_alpn_rule_matches"], 1)
        self.assertFalse(value["exact_redacted_feature_histograms_equal"])


if __name__ == "__main__":
    unittest.main()
