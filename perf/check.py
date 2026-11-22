#!/usr/bin/env python3
"""Compares a performance run with perf/baseline.json and fails on a regression.

    perf/check.py [--baseline perf/baseline.json] [--macro FILE] [--criterion DIR]
                  [--mode gates|regression] [--strict] [--update [--reference]]

* The macro file is the JSON of `perf_macro_lan` (target/tmp/perf-macro.json by default): the
  LAN end-to-end flow repeated N times, aggregated.
* The criterion directory is `target/criterion`; every `<group>/<bench>/new/estimates.json`
  gives one microbenchmark (mean, nanoseconds).

Two kinds of limit, both in the baseline file:

* `gate`  (macro) / `max_ns` (micro): an absolute budget. For the macro metrics the gates are the
  Gate 1 numbers of docs/execution-phase.md (added latency <= 40 ms p95 on LAN, typing and
  scrolling <= 1.5 cores, idle about 0 CPU and bandwidth). The micro budgets are deliberately
  generous (about 20x what a quiet machine measures): they catch an algorithmic regression, not
  noise. Always checked.
* `baseline` / `baseline_ns` with `regress_pct` (and an absolute `slack`): a relative limit against
  numbers recorded on the dedicated runner. Checked only in `--mode regression`, and only when
  the baseline file says `"reference": true` (recorded on that runner). A file recorded on a
  development machine is `"reference": false` and is not used for relative checks.

A macro result taken on a noisy host (`noisy: true`: load average above half the CPUs) or from a
debug build cannot prove a latency or CPU gate: those gates are reported as warnings unless
`--strict` is given (the dedicated runner's workflow does). Exit status 1 on any failure.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def load(path):
    with open(path) as f:
        return json.load(f)


def criterion_means(directory):
    """{ 'group/bench[/param]': mean_ns } from a criterion output directory."""
    out = {}
    for dirpath, _dirs, files in os.walk(directory):
        if os.path.basename(dirpath) != "new" or "estimates.json" not in files:
            continue
        rel = os.path.relpath(os.path.dirname(dirpath), directory)
        out[rel.replace(os.sep, "/")] = load(os.path.join(dirpath, "estimates.json"))["mean"]["point_estimate"]
    return out


def check_macro(base, result, mode, strict, problems, warnings, lines):
    metrics = result.get("metrics", {})
    reference = base.get("recorded", {}).get("reference", False)
    # Only a quiet release run can prove a gate that depends on timing.
    soft = (result.get("noisy") or not result.get("release_build")) and not strict
    why = []
    if result.get("noisy"):
        why.append("noisy host (load %.1f on %s CPUs)" % (result.get("loadavg_1m", 0), result.get("cpus", "?")))
    if not result.get("release_build"):
        why.append("debug build")
    for name, rule in base.get("macro", {}).items():
        if name not in metrics:
            problems.append("macro metric %s is missing from the result" % name)
            continue
        v = metrics[name]
        gate, ref, pct, slack = rule.get("gate"), rule.get("baseline"), rule.get("regress_pct"), rule.get("slack", 0)
        lines.append("macro %-30s %12.4f  gate %-8s baseline %s" % (name, v, gate, ref))
        if gate is not None and not v <= gate:
            msg = "%s = %.4f exceeds the gate %.4f" % (name, v, gate)
            if rule.get("timing") and soft:
                warnings.append(msg + " (not enforced: " + ", ".join(why) + ")")
            else:
                problems.append(msg)
        if mode == "regression" and reference and ref is not None and pct is not None:
            limit = ref * (1 + pct / 100.0) + slack
            if not v <= limit:
                msg = "%s = %.4f is more than %d%% above the baseline %.4f (limit %.4f)" % (name, v, pct, ref, limit)
                if rule.get("timing") and soft:
                    warnings.append(msg + " (not enforced: " + ", ".join(why) + ")")
                else:
                    problems.append(msg)


def check_micro(base, means, mode, problems, warnings, lines):
    reference = base.get("recorded", {}).get("reference", False)
    for name, rule in base.get("micro", {}).items():
        if name not in means:
            warnings.append("microbenchmark %s was not run" % name)
            continue
        v = means[name]
        lines.append("micro %-55s %12.1f ns  max %s baseline %s" % (name, v, rule.get("max_ns"), rule.get("baseline_ns")))
        if rule.get("max_ns") is not None and v > rule["max_ns"]:
            problems.append("%s = %.1f ns exceeds the budget %.1f ns" % (name, v, rule["max_ns"]))
        ref, pct = rule.get("baseline_ns"), rule.get("regress_pct")
        if mode == "regression" and reference and ref is not None and pct is not None:
            limit = ref * (1 + pct / 100.0)
            if v > limit:
                problems.append("%s = %.1f ns is more than %d%% above the baseline %.1f ns" % (name, v, pct, ref))
    for name in sorted(set(means) - set(base.get("micro", {}))):
        warnings.append("microbenchmark %s has no entry in the baseline (run --update)" % name)


def update(base, result, means, reference):
    """Writes measured numbers into the baseline, keeping gates, budgets and percentages."""
    import datetime
    import platform

    base.setdefault("recorded", {})
    base["recorded"].update({
        "date": datetime.date.today().isoformat(),
        "machine": platform.node() if reference else "development machine",
        "reference": bool(reference),
        "noisy": bool(result and result.get("noisy")),
        "cpus": result.get("cpus") if result else None,
        "loadavg_1m": result.get("loadavg_1m") if result else None,
        "release_build": bool(result and result.get("release_build")),
        "runs": result.get("runs") if result else None,
    })
    if result:
        for name, rule in base.get("macro", {}).items():
            if name in result.get("metrics", {}):
                rule["baseline"] = round(result["metrics"][name], 4)
    for name, v in means.items():
        rule = base.setdefault("micro", {}).setdefault(name, {"regress_pct": 30})
        rule["baseline_ns"] = round(v, 1)
        # A new entry gets a budget 20x what was just measured (rounded up to 100 ns).
        rule.setdefault("max_ns", max(100.0, round(v * 20 / 100.0 + 0.5) * 100.0))
    return base


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baseline", default=os.path.join(HERE, "baseline.json"))
    ap.add_argument("--macro", default=os.path.join(ROOT, "target", "tmp", "perf-macro.json"))
    ap.add_argument("--criterion", default=os.path.join(ROOT, "target", "criterion"))
    ap.add_argument("--mode", choices=["gates", "regression"], default="gates")
    ap.add_argument("--strict", action="store_true", help="enforce timing gates even on a noisy host or a debug build")
    ap.add_argument("--update", action="store_true", help="write the measured numbers into the baseline")
    ap.add_argument("--reference", action="store_true", help="with --update: this is the dedicated runner")
    a = ap.parse_args(argv)

    base = load(a.baseline)
    result = load(a.macro) if os.path.exists(a.macro) else None
    means = criterion_means(a.criterion) if os.path.isdir(a.criterion) else {}
    if a.update:
        updated = update(base, result, means, a.reference)
        with open(a.baseline, "w") as f:
            json.dump(updated, f, indent=2, sort_keys=False)
            f.write("\n")
        print("baseline updated (%s)" % ("reference runner" if a.reference else "development machine; relative checks stay off"))
        return 0

    problems, warnings, lines = [], [], []
    if result is None:
        problems.append("no macro result at %s (run perf/run.sh)" % a.macro)
    else:
        check_macro(base, result, a.mode, a.strict, problems, warnings, lines)
    if not means:
        warnings.append("no criterion results under %s" % a.criterion)
    else:
        check_micro(base, means, a.mode, problems, warnings, lines)
    print("\n".join(lines))
    for w in warnings:
        print("WARN  " + w)
    for p in problems:
        print("FAIL  " + p)
    print("%s: %d failure(s), %d warning(s), mode %s%s" % (
        "FAILED" if problems else "ok", len(problems), len(warnings), a.mode, ", strict" if a.strict else ""))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
