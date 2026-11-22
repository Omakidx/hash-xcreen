#!/usr/bin/env python3
"""Tests of perf/check.py: python3 -I perf/test_check.py"""
import copy
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check  # noqa: E402

BASE = {
    "recorded": {"reference": True},
    "macro": {
        "typing_latency_p95_ms": {"gate": 40, "baseline": 12.0, "regress_pct": 25, "slack": 2, "timing": True},
        "idle_cores": {"gate": 0.05, "baseline": 0.01, "regress_pct": 100, "slack": 0.01},
    },
    "micro": {"media_header/encode": {"max_ns": 1000, "baseline_ns": 20, "regress_pct": 30}},
}
GOOD = {"noisy": False, "release_build": True, "metrics": {"typing_latency_p95_ms": 14.0, "idle_cores": 0.012}}


def run(base, result, means, mode="gates", strict=False):
    problems, warnings, lines = [], [], []
    check.check_macro(base, result, mode, strict, problems, warnings, lines)
    check.check_micro(base, means, mode, problems, warnings, lines)
    return problems, warnings


class Check(unittest.TestCase):
    def test_a_good_run_passes_both_modes(self):
        for mode in ("gates", "regression"):
            p, w = run(BASE, GOOD, {"media_header/encode": 22}, mode)
            self.assertEqual(p, [], mode)

    def test_the_gate_fails_in_either_mode(self):
        r = copy.deepcopy(GOOD)
        r["metrics"]["typing_latency_p95_ms"] = 41
        self.assertTrue(any("gate" in x for x in run(BASE, r, {}, "gates")[0]))

    def test_a_relative_regression_fails_only_in_regression_mode_on_a_reference_baseline(self):
        r = copy.deepcopy(GOOD)
        r["metrics"]["typing_latency_p95_ms"] = 20  # +67 %, still under the 40 ms gate
        self.assertEqual(run(BASE, r, {}, "gates")[0], [])
        self.assertTrue(any("above the baseline" in x for x in run(BASE, r, {}, "regression")[0]))
        dev = copy.deepcopy(BASE)
        dev["recorded"]["reference"] = False
        self.assertEqual(run(dev, r, {}, "regression")[0], [])

    def test_micro_budget_and_relative_limit(self):
        self.assertTrue(any("budget" in x for x in run(BASE, GOOD, {"media_header/encode": 2000})[0]))
        self.assertTrue(any("above the baseline" in x for x in run(BASE, GOOD, {"media_header/encode": 30}, "regression")[0]))
        self.assertEqual(run(BASE, GOOD, {"media_header/encode": 30}, "gates")[0], [])

    def test_a_noisy_host_cannot_prove_or_fail_a_timing_gate_unless_strict(self):
        r = copy.deepcopy(GOOD)
        r["noisy"] = True
        r["metrics"]["typing_latency_p95_ms"] = 90
        p, w = run(BASE, r, {})
        self.assertEqual(p, [])
        self.assertTrue(any("not enforced" in x for x in w))
        self.assertTrue(run(BASE, r, {}, strict=True)[0])
        # A CPU gate is not a timing gate: it is enforced anyway.
        r["metrics"]["idle_cores"] = 0.3
        self.assertTrue(run(BASE, r, {})[0])

    def test_a_missing_metric_fails(self):
        r = copy.deepcopy(GOOD)
        del r["metrics"]["idle_cores"]
        self.assertTrue(any("missing" in x for x in run(BASE, r, {})[0]))

    def test_criterion_means_are_found_in_nested_output(self):
        with tempfile.TemporaryDirectory() as d:
            for rel, v in (("media_header/encode", 12.5), ("link_video_frame/read_and_parse/512", 900.0)):
                p = os.path.join(d, *rel.split("/"), "new")
                os.makedirs(p)
                with open(os.path.join(p, "estimates.json"), "w") as f:
                    json.dump({"mean": {"point_estimate": v}}, f)
            self.assertEqual(
                check.criterion_means(d),
                {"media_header/encode": 12.5, "link_video_frame/read_and_parse/512": 900.0},
            )

    def test_update_records_numbers_and_keeps_gates(self):
        b = copy.deepcopy(BASE)
        out = check.update(b, GOOD, {"media_header/encode": 25.0, "new/bench": 500.0}, reference=False)
        self.assertFalse(out["recorded"]["reference"])
        self.assertEqual(out["macro"]["typing_latency_p95_ms"]["gate"], 40)
        self.assertEqual(out["macro"]["typing_latency_p95_ms"]["baseline"], 14.0)
        self.assertEqual(out["micro"]["media_header/encode"]["max_ns"], 1000)
        self.assertEqual(out["micro"]["new/bench"]["baseline_ns"], 500.0)
        self.assertGreaterEqual(out["micro"]["new/bench"]["max_ns"], 10_000)


if __name__ == "__main__":
    unittest.main()
