"""Options 2 and 3 of the guide: Granite as the classifier, with or without a
LoRA fine-tune, measured on the same splits as the linear baseline.

    python training/train_lora.py               # option 3, model from config.json
    python training/train_lora.py --zero-shot   # option 2
    python training/train_lora.py --model <id>  # another model

The model is Granite 4 of about 800M parameters (training/config.json; confirm
the id, the size and the Apache-2.0 licence on its card). The script refuses a
model of 1.5B parameters or more (ADR-0005). Needs a CUDA GPU to train in
reasonable time (the RTX 4070 PC). Writes the adapter to
training/out/lora/adapter and predictions plus metrics to training/out/lora/.
"""

import argparse
import json
import sys
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig
from transformers import AutoModelForCausalLM, AutoTokenizer, EarlyStoppingCallback
from trl import SFTConfig, SFTTrainer

import common
import evaluate


def rows(split):
    path = common.HERE / "out" / "dataset" / f"{split}.jsonl"
    return [row for _, row in common.load_jsonl(path)] if path.exists() else []


def oversample(examples, share):
    """Repeats the non-`low` examples until they are about `share` of the
    training set. Real calls are almost all `low`; without this the model
    learns to answer `low` to everything. Only training: val and test keep
    the real proportions."""
    risky = [e for e in examples if e["label"] != "low"]
    low = len(examples) - len(risky)
    if not risky or not low or share <= 0:
        return examples
    copies = max(1, round(share * low / ((1 - share) * len(risky))))
    return examples + risky * (copies - 1)


def as_dataset(examples):
    return Dataset.from_list([{"prompt": common.prompt(e), "completion": " " + e["label"]} for e in examples])


@torch.no_grad()
def predict(model, tokenizer, examples):
    model.eval()
    device = next(model.parameters()).device
    out = []
    for example in examples:
        inputs = tokenizer(common.prompt(example), return_tensors="pt").to(device)
        generated = model.generate(**inputs, max_new_tokens=4, do_sample=False, pad_token_id=tokenizer.eos_token_id)
        answer = tokenizer.decode(generated[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
        out.append(common.parse_label(answer))
    return out


def main():
    config = json.loads((common.HERE / "config.json").read_text(encoding="utf-8"))
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model", default=config["model"], help="Hugging Face id of the Granite model")
    parser.add_argument("--zero-shot", action="store_true", help="measure the base model, no training")
    parser.add_argument("--epochs", type=float, default=config["epochs"])
    parser.add_argument("--lr", type=float, default=config["learning_rate"])
    parser.add_argument("--batch", type=int, default=config["batch_size"])
    parser.add_argument("--max-len", type=int, default=config["max_length"])
    parser.add_argument("--out", default=str(common.HERE / "out" / "lora"))
    parser.add_argument("--final", action="store_true", help="train on every split (the model to ship); nothing held out")
    args = parser.parse_args()
    if args.model.startswith("CONFIRM"):
        print("set the Granite model id in training/config.json (or pass --model)", file=sys.stderr)
        return 1

    train, val, test = rows("train"), rows("val"), rows("test")
    if args.final:
        # The held-out runs measured generalisation; the shipped model learns
        # from all of it. Its measurement is the separate stress test.
        train, val, test = train + val + test, [], []
    if not train and not args.zero_shot:
        print("no training data; run prepare.py first", file=sys.stderr)
        return 1
    train = oversample(train, config.get("risky_share", 0.0))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    bf16 = torch.cuda.is_available() and torch.cuda.is_bf16_supported()
    model = AutoModelForCausalLM.from_pretrained(args.model, torch_dtype=torch.bfloat16 if bf16 else torch.float32)
    parameters = sum(p.numel() for p in model.parameters())
    print(f"{args.model}: {parameters / 1e6:.0f}M parameters")
    if parameters >= config["max_parameters"]:
        print("1.5B parameters or more cannot run in the Core (ADR-0005)", file=sys.stderr)
        return 1
    # Granite 4.0 350M is dense (no experts) but declares a router loss
    # coefficient, which makes TRL add a load-balancing loss it cannot compute.
    dense = not getattr(model.config, "num_local_experts", 0)
    if torch.cuda.is_available():
        model = model.to("cuda")

    if not args.zero_shot:
        sft_config = SFTConfig(
            output_dir=str(out / "checkpoints"),
            num_train_epochs=args.epochs,
            learning_rate=args.lr,
            per_device_train_batch_size=args.batch,
            per_device_eval_batch_size=args.batch,
            gradient_accumulation_steps=config["gradient_accumulation_steps"],
            gradient_checkpointing=True,
            eval_strategy="epoch" if val else "no",
            save_strategy="epoch",
            load_best_model_at_end=bool(val),
            metric_for_best_model="eval_loss",
            greater_is_better=False,
            save_total_limit=2,
            logging_steps=10,
            max_length=args.max_len,
            completion_only_loss=True,
            bf16=bf16,
            report_to=[],
            router_aux_loss_coef=0.0 if dense else None,
        )
        # LoRA on every linear layer: small adapters, easy to version.
        settings = config["lora"]
        lora = LoraConfig(
            r=settings["r"],
            lora_alpha=settings["alpha"],
            lora_dropout=settings["dropout"],
            target_modules=settings["target_modules"],
            task_type="CAUSAL_LM",
        )
        trainer = SFTTrainer(
            model=model,
            args=sft_config,
            train_dataset=as_dataset(train),
            eval_dataset=as_dataset(val) if val else None,
            processing_class=tokenizer,
            peft_config=lora,
            callbacks=[EarlyStoppingCallback(early_stopping_patience=2)] if val else [],
        )
        trainer.train()
        trainer.save_model(str(out / "adapter"))
        tokenizer.save_pretrained(str(out / "adapter"))
        model = trainer.model

    mode = "zero-shot" if args.zero_shot else "lora"
    report = {"model": args.model, "mode": mode}
    for name, examples in [("val", val), ("test", test)]:
        if not examples:
            continue
        predicted = predict(model, tokenizer, examples)
        common.write_jsonl(out / f"{mode}-{name}-predictions.jsonl", [{**e, "pred": p} for e, p in zip(examples, predicted)])
        result = evaluate.metrics([e["label"] for e in examples], predicted)
        evaluate.show(result, f"{mode} on {name}")
        report[name] = result
    (out / f"{mode}-metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
