"""Reproducible AST ablation. Run: python -m evaluation.compare_context."""

import argparse
import json
from pathlib import Path

from evaluation.evaluate import load_ground_truth, get_detected_lines, calculate_metrics
from secret_guard.main import SecretGuard

ROOT = Path(__file__).resolve().parent.parent


def finish(guard, raw):
    filtered = guard.secret_filter.filter_findings(raw)
    allowed = guard.allowlist.filter_findings(filtered)
    return guard.policy_engine.evaluate(guard._merge_findings(allowed))


def old_dataset(guard, name):
    base = ROOT / "dataset"
    if name == "test":
        base /= "test"
    rows = load_ground_truth(base / ("ground_truth_test.csv" if name == "test" else "ground_truth.csv"))
    labels = {(r["filename"], r["line"]): r["expected_secret"] for r in rows}
    raw = []
    for category in ("positive", "negative"):
        for path in guard._collect_files(base / category):
            raw.extend(guard.scanner.scan_file(path))
    found = get_detected_lines(finish(guard, raw), base)
    tp = sum(v == 1 and k in found for k, v in labels.items())
    fn = sum(v == 1 and k not in found for k, v in labels.items())
    fp = sum(v == 0 and k in found for k, v in labels.items()) + len(found - labels.keys())
    tn = sum(v == 0 and k not in found for k, v in labels.items())
    return {"unit": "file and line", "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            **calculate_metrics(tp, fp, fn, tn)}


def challenge(guard, cases):
    tp = fp = fn = 0
    details = []
    for case in cases:
        raw = guard.scanner.scan_text(case["code"], case["id"] + ".py")
        predicted = {(f["line"], f["secret"]) for f in finish(guard, raw)}
        expected = {tuple(item) for item in case["expected"]}
        hit, extra, missed = len(predicted & expected), len(predicted - expected), len(expected - predicted)
        tp += hit
        fp += extra
        fn += missed
        details.append({"id": case["id"], "group": case["group"],
                        "tp": hit, "fp": extra, "fn": missed})
    metrics = calculate_metrics(tp, fp, fn, 0)
    # True negatives are undefined at arbitrary extracted-value granularity.
    metrics.pop("accuracy")
    return {"unit": "case, line and exact decoded secret value", "cases": len(cases),
            "expected_secrets": sum(len(c["expected"]) for c in cases),
            "tp": tp, "fp": fp, "fn": fn, **metrics, "details": details}


def run():
    cases = json.loads((ROOT / "evaluation/context_cases.json").read_text(encoding="utf-8"))
    results = {"note": "Authored development challenge, not an independent held-out benchmark. No external-tool comparison.",
               "baseline": {}, "python_ast": {}}
    for enabled, name in [(False, "baseline"), (True, "python_ast")]:
        guard = SecretGuard(enable_python_context=enabled)
        for dataset in ("development", "test"):
            results[name][dataset] = old_dataset(guard, dataset)
        results[name]["context_challenge"] = challenge(guard, cases)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optional JSON result path")
    args = parser.parse_args()
    results = run()
    rendered = json.dumps(results, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    for name in ("baseline", "python_ast"):
        for dataset, result in results[name].items():
            print(name, dataset, {k: v for k, v in result.items() if k != "details"})
