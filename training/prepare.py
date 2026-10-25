"""Builds the dataset: the rule catalogue's examples plus the team's JSONL files,
validated, deduplicated and split by family (docs/ENTRENAMIENTO-GRANITE.md).

    python training/prepare.py                       # catalogue + training/data/*.jsonl
    python training/prepare.py --input more.jsonl    # extra files
    python training/prepare.py --no-catalogue

Writes training/out/dataset/{train,val,test}.jsonl and stats.json. Exits 1 if
any input example is invalid, so nothing is trained on data nobody checked.
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import common

FIELD_KEYS = {"command": "command", "path": "path", "url": "url"}


def from_catalogue(path):
    """`fire` examples carry the rule's severity, `deny` examples are `low`.
    Both share the rule's family so they land in the same split."""
    rules = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = []
    for rule in rules:
        examples = rule.get("examples") or {}
        tool = (rule.get("tools") or ["bash"])[0]
        key = FIELD_KEYS.get(rule.get("field", "command"), "command")
        for text, label in [(t, rule["severity"]) for t in examples.get("fire", [])] + [
            (t, "low") for t in examples.get("deny", [])
        ]:
            rows.append(
                {
                    "tool": tool,
                    "args": {key: text},
                    "cwd": "/work",
                    "label": label,
                    "family": rule["id"],
                    "source": "catalogue",
                }
            )
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input", action="append", default=[], help="extra JSONL file")
    parser.add_argument("--catalogue", default=str(common.HERE.parent / "detect" / "rules" / "default.json"))
    parser.add_argument("--no-catalogue", action="store_true")
    parser.add_argument("--out", default=str(common.HERE / "out" / "dataset"))
    args = parser.parse_args()

    sources = common.allowed_sources()
    rows, bad = [], []
    if not args.no_catalogue:
        rows += from_catalogue(args.catalogue)
    inputs = sorted((common.HERE / "data").glob("*.jsonl")) + [Path(p) for p in args.input]
    for path in inputs:
        for number, example in common.load_jsonl(path):
            issues = common.problems(example, sources)
            if issues:
                bad.append(f"{path}:{number}: {'; '.join(issues)}")
            else:
                rows.append(example)
    for row in rows:
        for issue in common.problems(row, sources):
            bad.append(f"catalogue {row['family']}: {issue}")
    if bad:
        print("invalid examples, nothing written:", *bad[:50], sep="\n  ", file=sys.stderr)
        return 1

    seen, unique = set(), []
    for row in rows:
        key = (row["tool"], json.dumps(row["args"], sort_keys=True), row.get("cwd", ""))
        if key not in seen:
            seen.add(key)
            row.setdefault("split", common.split_of(row["family"]))
            unique.append(row)

    out = Path(args.out)
    for split in common.SPLITS:
        common.write_jsonl(out / f"{split}.jsonl", [r for r in unique if r["split"] == split])
    stats = {
        "examples": len(unique),
        "duplicates_dropped": len(rows) - len(unique),
        "by_split_and_label": {
            split: dict(Counter(r["label"] for r in unique if r["split"] == split))
            for split in common.SPLITS
        },
        "by_source": dict(Counter(r["source"] for r in unique)),
        "families": len({r["family"] for r in unique}),
    }
    (out / "stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
