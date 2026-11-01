"""Run a small deterministic check against the illustrative labelled scenarios.

This measures only the phrase-rule baseline. It does not evaluate Gemini, live STT,
real-world performance, or generalization beyond this small hand-written set.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import main  # noqa: E402

SCENARIOS = Path(__file__).with_name("scenarios.json")
INCLUDED_LABELS = {"high_risk", "safe_advice", "neutral"}


def main_eval() -> None:
    scenarios = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    tp = fp = tn = fn = 0
    skipped = []
    rows = []
    for scenario in scenarios:
        label = scenario["label"]
        result = main.analyse_transcript(scenario["transcript"])
        if label not in INCLUDED_LABELS:
            skipped.append(scenario["id"])
            continue
        expected = label == "high_risk"
        predicted = result["risk_score"] > 0
        if expected and predicted:
            tp += 1
        elif expected and not predicted:
            fn += 1
        elif not expected and predicted:
            fp += 1
        else:
            tn += 1
        rows.append((scenario["id"], label, result["risk_score"], "FLAG" if predicted else "NO FLAG"))

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    print("SunoSafe phrase-rule baseline evaluation (illustrative scenarios only)")
    print("Scenario                    Label              Score   Result")
    print("-" * 72)
    for scenario_id, label, score, result in rows:
        print(f"{scenario_id:28} {label:18} {score:5}   {result}")
    print("-" * 72)
    print(f"TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print(f"Precision={precision:.2f}  Recall={recall:.2f}")
    print(f"Not scored in binary metrics (ambiguous/victim-help): {', '.join(skipped) or 'none'}")
    print("NOTE: This is not a real-world accuracy estimate or a calibrated fraud detector.")


if __name__ == "__main__":
    main_eval()