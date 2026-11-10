import unittest
import json
import math

import analyze


class DetectorChecks(unittest.TestCase):
    def test_fit_agrees_with_scalar_logistic_optimum(self):
        # Symmetric standardized x={-1,+1}, y={0,1}: intercept=0 and
        # L2=1 optimum solves beta=1/(1+exp(beta)). Independent scalar root.
        lo, hi = 0., 1.
        for _ in range(60):
            mid = (lo + hi) / 2
            if mid > 1 / (1 + math.exp(mid)):
                hi = mid
            else:
                lo = mid
        model = analyze.logistic([[-1.], [1.]], [0, 1])
        self.assertAlmostEqual(model[2][0], 0.)
        self.assertAlmostEqual(model[2][1], (lo+hi)/2, places=9)
        self.assertAlmostEqual(analyze.predict(model, [[1.]])[0], (lo+hi)/2, places=9)

    def test_fit_rejects_missing_class_and_nonfinite_input(self):
        for x, y in (([[1.], [2.]], [1, 1]), ([[float("nan")], [2.]], [0, 1])):
            with self.assertRaises(ValueError):
                analyze.logistic(x, y)

    def test_detector_result_is_strict_json_and_heldout_cannot_change_fit(self):
        rows = [{"group": group, "mode": mode, "split": split,
                 "features": {"signal": float(group + (5 if mode == "p0" else 0))}}
                for group, split in enumerate(("train", "train", "heldout", "heldout"))
                for mode in ("native", "p0")]
        first = analyze.detector_result(rows, "p0", ["signal"], "p0")
        json.dumps(first, allow_nan=False)
        for row in rows:
            if row["split"] == "heldout":
                row["features"]["signal"] *= -100.
        second = analyze.detector_result(rows, "p0", ["signal"], "p0")
        self.assertEqual(first["threshold"], second["threshold"])
        self.assertEqual(first["largest_standardized_coefficients"], second["largest_standardized_coefficients"])
        self.assertNotEqual(first["auc"], second["auc"])

    def test_auc_ties_and_reversal(self):
        self.assertEqual(analyze.auc([0, 1], [4, 4]), .5)
        self.assertEqual(analyze.auc([0, 1], [-1, 1]), 1.)
        self.assertEqual(analyze.auc([0, 1], [1, -1]), 0.)
        self.assertAlmostEqual(analyze.auc([0, 0, 1, 1], [0, 2, 1, 2]), .625)

    def test_packet_window_ignores_identity_and_nonpacket_events(self):
        packets = [{"kind": "packet", "dir": "up", "n": 70, "t_ns": 0},
                   {"kind": "packet", "dir": "up", "n": 100, "t_ns": 1000000000},
                   {"kind": "packet", "dir": "down", "n": 200, "t_ns": 1500000000},
                   {"kind": "packet", "dir": "down", "n": 1300, "t_ns": 2000000000},
                   {"kind": "forwarded", "dir": "up", "n": 100, "t_ns": 1200000000}]
        a = analyze.features(packets, 1000000000, 2000000000)
        self.assertEqual(a["up_packets_per_second"], 1.)
        self.assertEqual(a["down_packets_per_second"], 1.)
        self.assertEqual(a["up_size_mean"], 100.)
        for p in packets:
            p.update(ip="should never be a feature", mode="proxy", seed=999, port=123)
        self.assertEqual(a, analyze.features(packets, 1000000000, 2000000000))

    def test_wilson_zero_observations_is_not_zero_risk(self):
        low, high = analyze.wilson(0, 16)
        self.assertAlmostEqual(low, 0.)
        self.assertGreater(high, .19)

    def test_refuses_group_fragment_leakage(self):
        common = {"group": 0, "workload": {"seed": 1}, "split": "train"}
        with self.assertRaisesRegex(ValueError, "crosses split"):
            analyze.report([dict(common, mode="native"), dict(common, mode="p0", split="heldout")], [])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            analyze.report([dict(common, mode="native"), dict(common, mode="native")], [])

    def test_refuses_empty_or_incomplete_comparison(self):
        with self.assertRaisesRegex(ValueError, "no complete"):
            analyze.report([], [])
        with self.assertRaisesRegex(ValueError, "train and heldout"):
            analyze.report([{"group": 1, "mode": mode, "split": "train", "workload": {}}
                            for mode in analyze.MODES], [])


if __name__ == "__main__":
    unittest.main()
