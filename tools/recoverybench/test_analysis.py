"""Regression tests for evidence interpretation, not network simulations."""
import json
from pathlib import Path
import tempfile
import unittest

import analyze_net


class AnalysisTests(unittest.TestCase):
    def test_go_nanosecond_timestamps_and_timezone(self):
        expected = 1794300311535962837
        self.assertEqual(analyze_net.stamp("2026-11-10T08:45:11.535962837Z"), expected)
        self.assertEqual(analyze_net.stamp("2026-11-10T11:45:11.535962837+03:00"), expected)

    def test_runner_failure_stays_in_denominator(self):
        group = analyze_net.aggregate([dict(profile="healthy", variant="test", status="runner_error",
                                             operations=None, sse=None)])[0]
        self.assertEqual(group["trials"], 1)
        self.assertEqual(group["completed"], 0)
        self.assertEqual(group["same_sse_target"], 0)

    def test_prefault_tcp_switch_is_not_h3_blackhole_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def write(name, value):
                (root/name).write_text(json.dumps(value))
            write("trial.json", dict(trial_id="synthetic", variant="test", profile="blackhole", status="completed"))
            write("proxy-events.json", [
                dict(role="client", msg="carrier attached", carrier="h3", observed_mono_ns=100, observed_wall_ns=100),
                dict(role="client", msg="carrier attached", carrier="h2", observed_mono_ns=200, observed_wall_ns=200),
            ])
            write("fault-events.json", [dict(event="fault_install_begin", mono_ns=300, wall_ns=300)])
            row = analyze_net.one(root)
            self.assertEqual(row["fault_timeline"]["carrier_at_fault"], "h2")
            self.assertFalse(row["fault_timeline"]["h3_active_when_udp_fault_installed"])
            self.assertEqual(row["fault_timeline"]["pre_fault_switches"], 1)
            self.assertNotIn("attach", row["fault_timeline"]["client_events_ms_from_fault_install_begin"])

    def test_epoch_bounds_survive_wall_clock_step(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def write(name, value):
                (root/name).write_text(json.dumps(value))
            write("trial.json", dict(trial_id="synthetic", variant="test", profile="blackhole", status="completed",
                                      benchmark_epoch_mono_bounds=dict(lower_ns=1_000_000_000, upper_ns=1_008_000_000, width_ns=8_000_000)))
            write("events.summary.json", dict(started_utc="2026-11-10T08:45:11Z", config=dict(http_rps=5)))
            write("proxy-events.json", [
                dict(role="client", msg="carrier attached", carrier="h3", observed_mono_ns=900_000_000, observed_wall_ns=1_000_000_000),
                dict(role="client", msg="carrier attached", carrier="h2", observed_mono_ns=3_000_000_000, observed_wall_ns=3_500_000_000),
            ])
            write("fault-events.json", [dict(event="fault_install_begin", mono_ns=2_000_000_000, wall_ns=2_100_000_000)])
            (root/"events.jsonl").write_text(json.dumps(dict(kind="http", status="success", seq=6, at_ns=999,
                                                           recorded_elapsed_ns=2_100_000_000))+"\n")
            row = analyze_net.one(root)
            self.assertFalse(row["clock_bridge"]["valid"])
            timeline = row["fault_timeline"]
            self.assertEqual(timeline["first_http_receipt_after_attach_ms_from_fault_bounds"], [1100, 1108])
            self.assertEqual(timeline["first_new_http_completion_ms_from_fault_bounds"], [1100, 1108])
            self.assertNotIn("first_http_receipt_after_attach_ms_from_fault", timeline)


if __name__ == "__main__":
    unittest.main()
