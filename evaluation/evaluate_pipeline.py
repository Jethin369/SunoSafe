"""Evaluate SunoSafe's production rule and contextual pipeline on labelled transcripts.

Default mode is offline and uses the exact production phrase-rule function.
Use --live-gemini to call the configured Gemini model through main.analyse_with_context.
Synthetic scenarios are regression tests, not a real-world accuracy benchmark.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT
sys.path.insert(0, str(PROJECT_ROOT))

try:
    import main  # type: ignore
except Exception as exc:  # give a Windows-friendly diagnostic
    raise SystemExit(
        "Could not import the project's main.py. Run this script from your existing "
        "SunoSafe virtual environment and make sure requirements.txt is installed. "
        f"Import error: {type(exc).__name__}: {exc}"
    ) from exc

SCENARIOS = Path(__file__).with_name("scenarios_v2.json")
RESULT_DIR = ROOT / "results"
BINARY_LABELS = {"suspicious", "benign"}
RISK_ASSESSMENTS = {"likely_scam_attempt", "suspicious_needs_verification"}
LABEL_ORDER = ["suspicious", "benign", "victim_help", "ambiguous"]


def select_balanced(scenarios: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """Round-robin labels so a small live sample is not accidentally all scams."""
    if limit <= 0 or limit >= len(scenarios):
        return list(scenarios)
    buckets: dict[str, list[dict[str, Any]]] = {}
    for label in LABEL_ORDER:
        items = [s for s in scenarios if s.get("label") == label]
        # Cycle through languages within each label before repeating a language.
        by_language: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in items:
            by_language[item.get("language", "Unknown")].append(item)
        ordered: list[dict[str, Any]] = []
        languages = sorted(by_language)
        while any(by_language.values()):
            for language in languages:
                if by_language[language]:
                    ordered.append(by_language[language].pop(0))
        buckets[label] = ordered
    selected: list[dict[str, Any]] = []
    while len(selected) < limit:
        progressed = False
        for label in LABEL_ORDER:
            if buckets[label] and len(selected) < limit:
                selected.append(buckets[label].pop(0))
                progressed = True
        if not progressed:
            break
    return selected


def validate_scenarios(scenarios: list[dict[str, Any]]) -> None:
    seen: set[str] = set()
    allowed = BINARY_LABELS | {"victim_help", "ambiguous"}
    for idx, scenario in enumerate(scenarios, start=1):
        if not isinstance(scenario, dict):
            raise ValueError(f"Scenario {idx} must be a JSON object")
        scenario_id = scenario.get("id")
        if not isinstance(scenario_id, str) or not scenario_id.strip() or scenario_id in seen:
            raise ValueError(f"Scenario {idx} has a missing or duplicate id: {scenario_id!r}")
        seen.add(scenario_id)
        if scenario.get("label") not in allowed:
            raise ValueError(f"Scenario {scenario_id} has unsupported label {scenario.get('label')!r}")
        if not isinstance(scenario.get("transcript"), str) or len(scenario["transcript"].strip()) < 12:
            raise ValueError(f"Scenario {scenario_id} has an empty/too-short transcript")
        if not isinstance(scenario.get("language"), str):
            raise ValueError(f"Scenario {scenario_id} has no language tag")


def metrics(rows: list[dict[str, Any]], threshold: int, result_key: str) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    by_language: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
    for row in rows:
        if row["label"] not in BINARY_LABELS or row.get(result_key) is None:
            continue
        expected = row["label"] == "suspicious"
        predicted = int(row[result_key]) >= threshold
        bucket = by_language[row["language"]]
        if expected and predicted:
            tp += 1; bucket["tp"] += 1
        elif not expected and predicted:
            fp += 1; bucket["fp"] += 1
        elif not expected and not predicted:
            tn += 1; bucket["tn"] += 1
        else:
            fn += 1; bucket["fn"] += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if tp + tn + fp + fn else 0.0
    return {
        "threshold": threshold, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "specificity": round(specificity, 4), "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "by_language": {
            lang: {
                **counts,
                "precision": round(counts["tp"] / (counts["tp"] + counts["fp"]), 4) if counts["tp"] + counts["fp"] else 0.0,
                "recall": round(counts["tp"] / (counts["tp"] + counts["fn"]), 4) if counts["tp"] + counts["fn"] else 0.0,
            }
            for lang, counts in sorted(by_language.items())
        },
    }


def print_metrics(title: str, result: dict[str, Any]) -> None:
    print(f"\n{title} (score >= {result['threshold']})")
    print(f"TP={result['tp']}  FP={result['fp']}  TN={result['tn']}  FN={result['fn']}")
    print(
        f"Precision={result['precision']:.3f}  Recall={result['recall']:.3f}  "
        f"Specificity={result['specificity']:.3f}  F1={result['f1']:.3f}  "
        f"Accuracy={result['accuracy']:.3f}"
    )
    print("By language:")
    for lang, vals in result["by_language"].items():
        print(f"  {lang:16} P={vals['precision']:.3f} R={vals['recall']:.3f} "
              f"TP={vals['tp']} FP={vals['fp']} TN={vals['tn']} FN={vals['fn']}")


async def run_live(rows: list[dict[str, Any]], delay: float) -> None:
    for idx, row in enumerate(rows, start=1):
        result = await main.analyse_with_context(row["transcript"], enabled=True)
        row["context_status"] = result.get("context_analysis_status", "unknown")
        row["context_assessment"] = result.get("contextual_assessment", "unclear_or_insufficient")
        row["context_victim_status"] = result.get("victim_status", "unclear")
        row["context_score"] = result.get("risk_score") if result.get("context_analysis_status") == "enhanced" else None
        row["context_failure"] = result.get("context_failure_reason", "")
        row["context_findings"] = [item.get("id") for item in result.get("findings", []) if isinstance(item, dict)]
        row["context_evidence_grounded"] = all(
            isinstance(item.get("evidence"), list)
            and all(isinstance(q, str) and main._quote_is_grounded(q, row["transcript"]) for q in item["evidence"])
            for item in result.get("findings", []) if isinstance(item, dict)
        )
        expected_assessment = row.get("expected_assessment", [])
        row["assessment_match"] = (
            row["context_assessment"] in expected_assessment
            if isinstance(expected_assessment, list) and expected_assessment else None
        )
        expected_victim = row.get("expected_victim_status", [])
        row["victim_status_match"] = (
            row["context_victim_status"] in expected_victim
            if isinstance(expected_victim, list) and expected_victim else None
        )
        if idx % 3 == 0 or idx == len(rows):
            print(f"Gemini evaluation progress: {idx}/{len(rows)}")
        if delay > 0 and idx < len(rows):
            await asyncio.sleep(delay)


def main_cli() -> int:
    parser = argparse.ArgumentParser(description="Evaluate SunoSafe rules and optional live Gemini contextual analysis.")
    parser.add_argument("--live-gemini", action="store_true", help="Call Gemini using the GEMINI_API_KEY from .env")
    parser.add_argument("--limit", type=int, default=12, help="Number of first scenarios to run (default: 12; use 0 for all)")
    parser.add_argument("--delay", type=float, default=0.8, help="Delay between live Gemini requests in seconds")
    parser.add_argument("--threshold", type=int, default=25, help="Risk-score threshold for the primary metrics")
    parser.add_argument("--output-dir", type=Path, default=RESULT_DIR, help="Directory for JSON and CSV reports")
    args = parser.parse_args()

    scenarios = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    validate_scenarios(scenarios)
    scenarios = select_balanced(scenarios, args.limit)
    rows: list[dict[str, Any]] = []
    print("SunoSafe evaluation — synthetic labelled transcript set")
    print(f"Mode: {'rules + LIVE Gemini' if args.live_gemini else 'offline production rules only'}")
    print(f"Scenarios loaded: {len(scenarios)}")
    print("Selection: balanced across suspicious, benign, victim-help and ambiguous labels")
    for case in scenarios:
        base = main.analyse_transcript(case["transcript"])
        row = dict(case)
        row["rule_score"] = base["risk_score"]
        row["rule_level"] = base["risk_level"]
        row["rule_findings"] = [item.get("id") for item in base.get("findings", [])]
        row["rule_flag_any"] = base["risk_score"] > 0
        row["rule_flag_threshold"] = base["risk_score"] >= args.threshold
        row["context_status"] = "not_run"
        rows.append(row)

    print("\nScenario                         Language         Label          Rule score  Rule findings")
    print("-" * 112)
    for row in rows:
        findings = ",".join(row["rule_findings"]) or "—"
        print(f"{row['id'][:32]:32} {row['language'][:15]:15} {row['label']:14} {row['rule_score']:>5}       {findings}")

    # Report both the legacy any-signal threshold and a more conservative elevated threshold.
    print_metrics("Phrase-rule baseline", metrics(rows, 1, "rule_score"))
    print_metrics("Phrase-rule baseline", metrics(rows, args.threshold, "rule_score"))

    live_rows = rows
    if args.live_gemini:
        if not main.GEMINI_API_KEY:
            print("\nERROR: GEMINI_API_KEY is not available to main.py. Check the project's .env file.")
            return 2
        print("\nCalling Gemini sequentially. This can take time and use API quota...")
        asyncio.run(run_live(live_rows, max(0.0, args.delay)))
        completed = [r for r in rows if r.get("context_status") == "enhanced"]
        failed = [r for r in rows if r.get("context_status") != "enhanced"]
        print(f"\nContextual requests completed: {len(completed)}/{len(rows)}")
        if failed:
            print("Incomplete requests (not scored as model results):")
            for r in failed:
                print(f"  {r['id']}: {r.get('context_status')} {r.get('context_failure', '')}")
        if completed:
            print_metrics("Hybrid contextual risk score", metrics(completed, 1, "context_score"))
            print_metrics("Hybrid contextual risk score", metrics(completed, args.threshold, "context_score"))
            assessments = {k: 0 for k in ["likely_scam_attempt", "suspicious_needs_verification", "apparently_legitimate", "unclear_or_insufficient"]}
            decided = 0
            correct = 0
            for r in completed:
                actual = r["label"]
                pred = r.get("context_assessment", "unclear_or_insufficient")
                assessments[pred] = assessments.get(pred, 0) + 1
                if actual in BINARY_LABELS and pred in {"likely_scam_attempt", "apparently_legitimate"}:
                    decided += 1
                    expected_suspicious = actual == "suspicious"
                    correct += int((pred == "likely_scam_attempt") == expected_suspicious)
            print("\nGemini assessment distribution:", assessments)
            scored_assessment_rows = [r for r in completed if r.get("assessment_match") is not None]
            if scored_assessment_rows:
                assessment_hits = sum(bool(r.get("assessment_match")) for r in scored_assessment_rows)
                print(f"Label-specific expected assessment match: {assessment_hits}/{len(scored_assessment_rows)}")
            binary_rows = [r for r in completed if r["label"] in BINARY_LABELS]
            decided_rows = [r for r in binary_rows if r.get("context_assessment") in {"likely_scam_attempt", "apparently_legitimate"}]
            correct_rows = [r for r in decided_rows if (r["label"] == "suspicious") == (r["context_assessment"] == "likely_scam_attempt")]
            print(f"Binary-decision coverage: {len(decided_rows)}/{len(binary_rows)}")
            if decided_rows:
                print(f"Accuracy among decisive assessments: {len(correct_rows) / len(decided_rows):.3f}")
            # Validate model's explicit assessments for ambiguous and victim-help examples.
            ambiguous_rows = [r for r in completed if r["label"] == "ambiguous"]
            if ambiguous_rows:
                hits = sum(bool(r.get("assessment_match")) for r in ambiguous_rows)
                print(f"Ambiguous-case expected assessment: {hits}/{len(ambiguous_rows)}")
            victim_rows = [r for r in completed if r["label"] == "victim_help"]
            if victim_rows:
                hits = sum(bool(r.get("victim_status_match")) for r in victim_rows)
                safe_scores = sum((r.get("context_score") or 0) == 0 for r in victim_rows)
                print(f"Victim-help handling: expected victim status={hits}/{len(victim_rows)}; zero active-risk score={safe_scores}/{len(victim_rows)}")
            ungrounded = [r["id"] for r in completed if not r.get("context_evidence_grounded", True)]
            print("Evidence grounding:", "PASS for all returned findings" if not ungrounded else f"Review ungrounded: {', '.join(ungrounded)}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_UTC")
    json_path = args.output_dir / f"sunosafe_eval_{stamp}.json"
    csv_path = args.output_dir / f"sunosafe_eval_{stamp}.csv"
    json_path.write_text(json.dumps({"mode": "live_gemini" if args.live_gemini else "rules_only", "threshold": args.threshold, "rows": rows}, ensure_ascii=False, indent=2), encoding="utf-8")
    fields = ["id", "language", "label", "rule_score", "rule_level", "rule_findings", "context_status", "context_score", "context_assessment", "assessment_match", "context_victim_status", "victim_status_match", "context_findings", "context_failure"]
    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            cleaned = dict(row)
            for key in ("rule_findings", "context_findings"):
                if isinstance(cleaned.get(key), list):
                    cleaned[key] = ";".join(cleaned[key])
            writer.writerow(cleaned)
    print(f"\nSaved detailed JSON: {json_path}")
    print(f"Saved spreadsheet-friendly CSV: {csv_path}")
    print("Reminder: synthetic test results are regression evidence, not real-world detection accuracy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main_cli())
