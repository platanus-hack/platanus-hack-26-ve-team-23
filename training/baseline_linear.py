"""Option 1 of the guide: feature hashing plus logistic regression, the
baseline every other model is compared against (ADR-0014). Runs on a CPU.

    python training/baseline_linear.py      # after prepare.py

Picks the regularisation on `val`, reports `val` and `test`, and writes
training/out/linear/model.json: the weights and exactly how the text is turned
into features, so the Core can reproduce it in Rust (not built yet).
"""

import json
import sys
from pathlib import Path

from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import LogisticRegression

import common
import evaluate

N_FEATURES = 2**16
VECTORIZER = dict(n_features=N_FEATURES, ngram_range=(1, 2), alternate_sign=False, lowercase=True, norm="l2")


def load(split, folder):
    path = Path(folder) / f"{split}.jsonl"
    rows = [row for _, row in common.load_jsonl(path)] if path.exists() else []
    return [common.render(r) for r in rows], [r["label"] for r in rows]


def main():
    data = common.HERE / "out" / "dataset"
    (train_x, train_y), (val_x, val_y), (test_x, test_y) = (load(s, data) for s in common.SPLITS)
    if len(set(train_y)) < 2:
        print("train has fewer than two labels; run prepare.py with more data", file=sys.stderr)
        return 1
    vectorizer = HashingVectorizer(**VECTORIZER)
    xs = {name: vectorizer.transform(x) for name, x in [("train", train_x), ("val", val_x), ("test", test_x)]}

    best = None
    for c in (0.1, 0.3, 1.0, 3.0, 10.0):
        model = LogisticRegression(C=c, class_weight="balanced", max_iter=5000)
        model.fit(xs["train"], train_y)
        if not val_y:
            best = (0.0, c, model)
            break
        score = evaluate.metrics(val_y, list(model.predict(xs["val"])))
        # Fewer misses first, then fewer false alarms.
        key = (-(score["miss_rate"] or 0.0), -(score["false_alarm_rate"] or 0.0))
        if best is None or key > best[0]:
            best = (key, c, model)
    _, c, model = best

    for name, x, y in [("val", xs["val"], val_y), ("test", xs["test"], test_y)]:
        if y:
            evaluate.show(evaluate.metrics(y, list(model.predict(x))), f"linear C={c} on {name}")

    out = common.HERE / "out" / "linear"
    out.mkdir(parents=True, exist_ok=True)
    (out / "model.json").write_text(
        json.dumps(
            {
                "kind": "hashing-logistic-regression",
                "features": {**VECTORIZER, "ngram_range": list(VECTORIZER["ngram_range"]),
                             "token_pattern": vectorizer.token_pattern, "hash": "murmurhash3_32, seed 0, absolute value modulo n_features"},
                "text": "common.render(example)",
                "labels": list(model.classes_),
                "intercept": model.intercept_.tolist(),
                "coef": model.coef_.tolist(),
                "C": c,
            }
        ),
        encoding="utf-8",
    )
    print(f"\nwrote {out / 'model.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
