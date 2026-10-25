"""Distils the trained corpus into the compact familiarity artifact the Core
embeds (ADR-0036). The classifier the demo ships is not Granite in the Core
(a GGUF runtime there is unbuilt and ADR-gated); it is this allowlist of what
our data shows is legitimate, so the policy can default-deny the rest.

    python training/export_familiarity.py        # after prepare.py

Reads the `low` examples of out/dataset (every split: they are all legitimate)
and writes detect/model/familiarity.json: the set of shell programs seen in
legitimate `bash` calls, plus the per-tool severity the policy gives an
unfamiliar call. Kept tiny and pure data, like detect/rules/default.json.
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path

import common

# What a severity means (ADR-0022): low allow, medium ask, high deny. An
# unfamiliar call is never silently allowed; writing/network is denied,
# reading is asked. The team tunes this table without touching Rust.
UNFAMILIAR_SEVERITY = {
    "bash": "high",      # the shell is the sharp edge: an unseen command is denied
    "write": "high",
    "edit": "high",
    "read": "medium",    # reading is asked, not blocked, so the agent can still work
    "webfetch": "medium",
}
DEFAULT_UNFAMILIAR = "medium"
# A program name: the first token, bare or a path, no shell metacharacters.
PROGRAM = re.compile(r"^[A-Za-z0-9][\w.+-]*$")


def program_of(command):
    """The program a shell line runs: its first bare token, `sudo`/`env`
    skipped. `None` when the line is not a plain command (a pipe into it, a
    variable assignment, a subshell): those stay unfamiliar."""
    tokens = command.strip().split()
    for token in tokens:
        if "=" in token and PROGRAM.match(token.split("=")[0] or "x"):
            continue  # VAR=value prefix
        name = token.rsplit("/", 1)[-1]
        if name in ("sudo", "doas", "env", "command", "exec", "nice", "nohup"):
            continue
        return name if PROGRAM.match(name) else None
    return None


def main():
    data = common.HERE / "out" / "dataset"
    programs = Counter()
    examples = 0
    for split in common.SPLITS:
        path = data / f"{split}.jsonl"
        if not path.exists():
            continue
        for _, row in common.load_jsonl(path):
            if row.get("label") != "low" or row.get("tool") != "bash":
                continue
            command = (row.get("args") or {}).get("command")
            if not isinstance(command, str):
                continue
            name = program_of(command)
            if name:
                programs[name] += 1
                examples += 1
    if not programs:
        print("no legitimate bash examples; run prepare.py first", file=sys.stderr)
        return 1

    artifact = {
        "kind": "familiarity-allowlist-v1",
        "note": "Legitimate shell programs distilled from the training corpus "
                "(catalogue + tldr, label low). An unfamiliar call is denied or "
                "asked per unfamiliar_severity (ADR-0036). Not Granite in the Core.",
        "source": "out/dataset low bash examples",
        "programs": sorted(programs),
        "unfamiliar_severity": UNFAMILIAR_SEVERITY,
        "default_unfamiliar_severity": DEFAULT_UNFAMILIAR,
        "stats": {"programs": len(programs), "examples": examples},
    }
    out = common.HERE.parent / "detect" / "model" / "familiarity.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(artifact, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"{len(programs)} programs from {examples} legitimate calls -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
