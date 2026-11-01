"""Run a small synthetic development-set check. This is not a real-world benchmark."""
from __future__ import annotations

import json
from pathlib import Path
from collections import defaultdict

from main import analyse_transcript

DATA_PATH = Path(__file__).parent / "evaluation" / "scenarios.jsonl"


def safe_div(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def main() -> None:
    examples = [json.loads(line) for line in DATA_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    counts = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    binary = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    per_case = []

    for example in examples:
        result = analyse_transcript(example["transcript"])
        predicted = {finding["id"] for finding in result["findings"]}
        expected = set(example["expected_findings"])
        for category in predicted | expected:
            if category in predicted and category in expected:
                counts[category]["tp"] += 1
            elif category in predicted:
                counts[category]["fp"] += 1
            else:
                counts[category]["fn"] += 1

        expected_risk = example["label"] == "risk"
        predicted_risk = bool(predicted)
        if expected_risk and predicted_risk:
            binary["tp"] += 1
        elif not expected_risk and predicted_risk:
            binary["fp"] += 1
        elif not expected_risk and not predicted_risk:
            binary["tn"] += 1
        else:
            binary["fn"] += 1

        per_case.append({"id": example["id"], "expected": sorted(expected), "predicted": sorted(predicted), "matched": predicted == expected})

    precision = safe_div(binary["tp"], binary["tp"] + binary["fp"])
    recall = safe_div(binary["tp"], binary["tp"] + binary["fn"])
    accuracy = safe_div(binary["tp"] + binary["tn"], sum(binary.values()))
    print("SunoSafe synthetic development set")
    print(f"Cases: {len(examples)} | positive: {sum(e['label'] == 'risk' for e in examples)} | negative: {sum(e['label'] == 'safe' for e in examples)}")
    print("IMPORTANT: synthetic, developer-authored examples only; do not interpret as real-world accuracy.\n")
    print(f"Binary risk-signal check: precision={precision:.0%}, recall={recall:.0%}, accuracy={accuracy:.0%}")
    print(f"TP={binary['tp']} FP={binary['fp']} TN={binary['tn']} FN={binary['fn']}\n")
    print("Per-category results:")
    for category in sorted(counts):
        c = counts[category]
        p = safe_div(c["tp"], c["tp"] + c["fp"])
        r = safe_div(c["tp"], c["tp"] + c["fn"])
        print(f"  {category:24} precision={p:.0%} recall={r:.0%} TP={c['tp']} FP={c['fp']} FN={c['fn']}")
    mismatches = [case for case in per_case if not case["matched"]]
    print(f"\nExact category matches: {len(per_case) - len(mismatches)}/{len(per_case)}")
    if mismatches:
        print("Category mismatches to review:")
        for case in mismatches:
            print(f"  {case['id']}: expected={case['expected']} predicted={case['predicted']}")


if __name__ == "__main__":
    main()
