"""Shows how HAWK decides on a set of commands: the rules, the familiarity
stage (ADR-0036) and the trained model, side by side, and the final outcome
the policy gives (ADR-0022). A read-only view for the demo; it trains nothing.

    python training/show_decisions.py                 # catalogue attack examples
    python training/show_decisions.py --model          # also ask the LoRA model
    python training/show_decisions.py --file cmds.txt  # one command per line

The attack commands come from the rule catalogue's own `fire` examples (written
by the team, detect/rules/default.json). No attacks are generated here.
"""

import argparse
import json
import sys
from pathlib import Path

import common
import rules

# ADR-0022 default thresholds: low allow, medium ask, high deny, critical deny.
RANK = {label: i for i, label in enumerate(common.LABELS)}


def familiarity(artifact):
    allow = set(artifact["programs"])
    sev = artifact["unfamiliar_severity"]
    default = artifact["default_unfamiliar_severity"]
    wrappers = {"sudo", "doas", "env", "command", "exec", "nice", "nohup"}

    def is_program(s):
        return bool(s) and s[0].isalnum() and all(c.isalnum() or c in "_.+-" for c in s)

    def program(cmd):
        for token in cmd.split():
            if "=" in token:
                pre = token.split("=", 1)[0]
                if pre == "" or is_program(pre):
                    continue
            name = token.rsplit("/", 1)[-1]
            if name in wrappers:
                continue
            return name if is_program(name) else None
        return None

    def check(call):
        if call["tool"] != "bash":
            return None
        cmd = (call.get("args") or {}).get("command")
        if not isinstance(cmd, str):
            return None
        name = program(cmd)
        if name is not None and name in allow:
            return None
        return sev.get(call["tool"], default)

    return check


def decision(severity):
    if severity is None:
        return "allow"
    if severity == "critical":
        return "DENY + aislar"
    if severity == "high":
        return "DENY"
    if severity == "medium":
        return "ASK"
    return "allow"


def attack_examples():
    catalogue = json.loads((common.HERE.parent / "detect" / "rules" / "default.json").read_text(encoding="utf-8"))
    out = []
    for rule in catalogue:
        tool = (rule.get("tools") or ["bash"])[0]
        field = rule.get("field", "command")
        for text in (rule.get("examples") or {}).get("fire", []):
            out.append({"tool": tool, "args": {field: text}, "cwd": "/work"})
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model", action="store_true", help="also show the LoRA model's own answer")
    parser.add_argument("--adapter", default=str(common.HERE / "out" / "lora-tldr" / "adapter"))
    parser.add_argument("--file", help="read commands from a file, one per line (bash)")
    args = parser.parse_args()
    try:  # the Windows console is cp1252 by default; keep accents readable
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    if args.file:
        calls = [{"tool": "bash", "args": {"command": line.strip()}, "cwd": "/work"}
                 for line in Path(args.file).read_text(encoding="utf-8").splitlines() if line.strip()]
    else:
        calls = attack_examples()

    engine = rules.Rules()
    fam = familiarity(json.loads((common.HERE.parent / "detect" / "model" / "familiarity.json").read_text(encoding="utf-8")))

    model_pred = None
    if args.model:
        import torch
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer
        import train_lora
        config = json.loads((common.HERE / "config.json").read_text(encoding="utf-8"))
        tok = AutoTokenizer.from_pretrained(args.adapter)
        base = AutoModelForCausalLM.from_pretrained(config["model"], torch_dtype=torch.float32)
        model = PeftModel.from_pretrained(base, args.adapter)
        if torch.cuda.is_available():
            model = model.to("cuda")
        model_pred = train_lora.predict(model, tok, [{**c, "label": "low"} for c in calls])

    header = f"{'comando':50}  {'regla':>9}  {'familiar':>8}  {'=> decision':15}"
    if args.model:
        header += "  modelo"
    print(header)
    print("-" * len(header))
    missed = 0
    for i, call in enumerate(calls):
        rule_sev = engine.severity(call)
        fam_sev = fam(call)
        top = max((s for s in (rule_sev, fam_sev) if s), key=RANK.get, default=None)
        text = (call["args"].get("command") or next(iter(call["args"].values())))[:48]
        row = f"{text:50}  {rule_sev or '-':>9}  {fam_sev or '-':>8}  {decision(top):15}"
        if args.model:
            m = model_pred[i]
            row += f"  {m or '?'}"
            if top in ("high", "critical") and m in ("low", None):
                missed += 1
        print(row)
    if args.model:
        dangerous = sum(1 for c in calls if (engine.severity(c) in ("high", "critical")))
        print(f"\nEl modelo solo habría dejado pasar {missed}/{dangerous} comandos peligrosos como low.")
        print("Las reglas + la familiaridad los detienen igual (columna => decision).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
