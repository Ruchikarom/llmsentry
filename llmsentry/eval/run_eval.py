"""
Run the scanner against the benign + malicious corpus and report
precision, recall, and false-positive rate at the configured threshold.

Usage:
    python eval/run_eval.py
    python eval/run_eval.py --threshold 0.4
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llmsentry.scanner import scan, SourceType  # noqa: E402

CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpus"


def load_corpus(filename: str) -> list[dict]:
    with open(CORPUS_DIR / filename) as f:
        return json.load(f)


def run(threshold: float) -> None:
    malicious = load_corpus("malicious.json")
    benign = load_corpus("benign.json")

    tp = fn = tn = fp = 0
    rows = []

    for item in malicious:
        result = scan(item["text"], source=SourceType(item["source"]))
        hit = result.score >= threshold
        tp += hit
        fn += not hit
        rows.append((item["id"], item["category"], "malicious", result.score, hit))

    for item in benign:
        result = scan(item["text"], source=SourceType(item["source"]))
        hit = result.score >= threshold
        fp += hit
        tn += not hit
        rows.append((item["id"], item["category"], "benign", result.score, hit))

    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")

    print(f"\n{'ID':<20} {'CATEGORY':<25} {'TRUE LABEL':<12} {'SCORE':<8} {'FLAGGED'}")
    print("-" * 80)
    for row in rows:
        id_, cat, label, score, hit = row
        marker = " <-- WRONG" if (label == "malicious") != hit else ""
        print(f"{id_:<20} {cat:<25} {label:<12} {score:<8.2f} {str(hit):<8}{marker}")

    print("\n--- Summary at threshold={:.2f} ---".format(threshold))
    print(f"Malicious detected (recall):     {tp}/{tp+fn}  ({recall:.1%})")
    print(f"Benign false positives:          {fp}/{fp+tn}  (FPR {fpr:.1%})")
    print(f"Precision:                       {precision:.1%}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--threshold", type=float, default=0.4)
    args = parser.parse_args()
    run(args.threshold)
