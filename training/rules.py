"""The Core's rules, in Python, for simulating HAWK while training.

A faithful port of `detect` on this branch: the data rules of
`detect/rules/default.json` (tools filter, one field, any pattern matches and
no exception matches) and the code rule `hawk.workspace.write` (any call with
a path that resolves outside `cwd` is `high`). Paths are resolved as the Core
does on the Raspberry Pi (Linux), so a Windows path is a relative path there.
The highest severity among the findings decides (detect/src/policy.rs).

    python training/rules.py      # self-test against every catalogue example
"""

import json
import posixpath
import re
import sys

import common

RANK = {label: i for i, label in enumerate(common.LABELS)}
PATH_FIELDS = ["path", "file_path", "to", "destination", "src"]
CATALOGUE = common.HERE.parent / "detect" / "rules" / "default.json"


def _field(call, field):
    args = call.get("args") or {}
    if field == "command":
        value = args.get("command")
    elif field == "path":
        value = next((args[k] for k in PATH_FIELDS if isinstance(args.get(k), str)), None)
    else:
        value = args.get("url")
    return value if isinstance(value, str) else None


class Rules:
    def __init__(self, path=CATALOGUE):
        self.rules = []
        for rule in json.loads(path.read_text(encoding="utf-8")):
            self.rules.append(
                {
                    "id": rule["id"],
                    "severity": rule["severity"],
                    "tools": rule.get("tools") or [],
                    "field": rule.get("field", "command"),
                    "patterns": [re.compile(p) for p in rule["patterns"]],
                    "exceptions": [re.compile(p) for p in rule.get("exceptions") or []],
                    "examples": rule.get("examples") or {},
                }
            )

    def findings(self, call):
        found = []
        for rule in self.rules:
            if rule["tools"] and call["tool"] not in rule["tools"]:
                continue
            value = _field(call, rule["field"])
            if value is None:
                continue
            if any(p.search(value) for p in rule["patterns"]) and not any(e.search(value) for e in rule["exceptions"]):
                found.append((rule["id"], rule["severity"]))
        if outside_workspace(call):
            found.append(("hawk.workspace.write", "high"))
        return found

    def severity(self, call):
        """The top severity of the findings; `None` when no rule fires."""
        found = self.findings(call)
        return max((s for _, s in found), key=RANK.get) if found else None


def outside_workspace(call):
    target = _field(call, "path")
    if target is None:
        return False
    cwd = posixpath.normpath(call.get("cwd") or "/")
    absolute = posixpath.normpath(target if target.startswith("/") else posixpath.join(cwd, target))
    return not (absolute == cwd or absolute.startswith(cwd.rstrip("/") + "/"))


def self_test():
    """Every `fire` example fires its rule and every `deny` example does not."""
    rules = Rules()
    bad = []
    for rule in rules.rules:
        tool = (rule["tools"] or ["bash"])[0]
        for text, should in [(t, True) for t in rule["examples"].get("fire", [])] + [
            (t, False) for t in rule["examples"].get("deny", [])
        ]:
            call = {"tool": tool, "args": {rule["field"]: text}, "cwd": "/work"}
            fired = any(i == rule["id"] for i, _ in rules.findings(call))
            if fired != should:
                bad.append(f"{rule['id']}: {text!r} fired={fired}")
    assert outside_workspace({"tool": "write", "args": {"path": "/etc/passwd"}, "cwd": "/work"})
    assert not outside_workspace({"tool": "write", "args": {"path": "src/a.py"}, "cwd": "/work"})
    return bad


if __name__ == "__main__":
    problems = self_test()
    print("\n".join(problems) if problems else "rules: every catalogue example behaves")
    sys.exit(1 if problems else 0)
