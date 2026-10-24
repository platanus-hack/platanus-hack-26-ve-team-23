"""Metrics of a classifier on one split (ADR-0010): per-class precision and
recall, the confusion matrix, and the two numbers that matter for HAWK.

- false alarms: legitimate calls (`low`) the model would ask about or deny;
- misses: `high` or `critical` calls the model would let through as `low`.

    python training/evaluate.py predictions.jsonl     # rows with "label" and "pred"
"""

import json
import sys

import common


def metrics(truth, predicted):
    labels = common.LABELS
    confusion = {t: {p: 0 for p in labels + ["none"]} for t in labels}
    for t, p in zip(truth, predicted):
        confusion[t][p if p in labels else "none"] += 1
    per_class = {}
    for label in labels:
        tp = confusion[label][label]
        fp = sum(confusion[t][label] for t in labels if t != label)
        fn = sum(confusion[label][p] for p in labels + ["none"] if p != label)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_class[label] = {"precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3), "support": tp + fn}
    legit = [p for t, p in zip(truth, predicted) if t == "low"]
    dangerous = [p for t, p in zip(truth, predicted) if t in ("high", "critical")]
    return {
        "examples": len(truth),
        "accuracy": round(sum(t == p for t, p in zip(truth, predicted)) / len(truth), 3) if truth else 0.0,
        "false_alarm_rate": round(sum(p != "low" for p in legit) / len(legit), 3) if legit else None,
        "miss_rate": round(sum(p in ("low", None) for p in dangerous) / len(dangerous), 3) if dangerous else None,
        "per_class": per_class,
        "confusion": confusion,
    }


def show(result, title):
    print(f"\n== {title}: {result['examples']} examples, accuracy {result['accuracy']}")
    print(f"   false alarms on legitimate calls: {result['false_alarm_rate']}")
    print(f"   high/critical let through as low: {result['miss_rate']}")
    for label, m in result["per_class"].items():
        print(f"   {label:9} precision {m['precision']:.3f}  recall {m['recall']:.3f}  f1 {m['f1']:.3f}  n={m['support']}")


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    rows = [row for _, row in common.load_jsonl(sys.argv[1])]
    result = metrics([r["label"] for r in rows], [r.get("pred") for r in rows])
    show(result, sys.argv[1])
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
