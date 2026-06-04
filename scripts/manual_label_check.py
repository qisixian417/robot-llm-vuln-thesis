# [数据质量] 从测试集随机抽50条生成CSV，人工标注后计算标注准确率，为论文数据标签噪声提供实测依据
#!/usr/bin/env python3
"""Sample 50 items from test set for manual label verification.

Usage:
  python scripts/manual_label_check.py --sample     # Generate CSV
  python scripts/manual_label_check.py --evaluate   # Compute accuracy after labeling
"""

import argparse
import csv
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEST_PATH = ROOT / "data" / "test_v2.jsonl"
OUTPUT_CSV = ROOT / "data" / "manual_label_check.csv"
SAMPLE_SIZE = 50

random.seed(42)


def load_jsonl(filepath: Path) -> list:
    samples = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def sample_and_export():
    if not TEST_PATH.exists():
        print(f"ERROR: {TEST_PATH} not found.")
        return

    samples = load_jsonl(TEST_PATH)
    print(f"Loaded {len(samples)} test samples")

    k = min(SAMPLE_SIZE, len(samples))
    selected = random.sample(samples, k)

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow([
            "id", "repo", "language", "cwe_id", "label",
            "code_snippet_first_20_lines", "your_verdict(correct/incorrect)", "notes"
        ])
        for s in selected:
            code = s.get("vulnerable_code", "") or s.get("code", "")
            snippet = "\n".join(code.splitlines()[:20])
            label_str = "VULNERABLE" if s.get("label") == 1 else "CLEAN"
            writer.writerow([
                s.get("id", ""),
                s.get("repo", ""),
                s.get("language", ""),
                s.get("cwe_id", ""),
                label_str,
                snippet,
                "",
                "",
            ])

    print(f"✓ Exported {k} samples to: {OUTPUT_CSV}")
    print(f"\nNext steps:")
    print(f"  1. Open {OUTPUT_CSV} in Excel/WPS")
    print(f"  2. For each row, read the code and current label")
    print(f"  3. In column 'your_verdict' write: correct or incorrect")
    print(f"  4. Save and run: python scripts/manual_label_check.py --evaluate")


def evaluate():
    if not OUTPUT_CSV.exists():
        print(f"ERROR: {OUTPUT_CSV} not found. Run --sample first.")
        return

    total = 0
    correct = 0
    incorrect = 0
    unmarked = 0

    with open(OUTPUT_CSV, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total += 1
            verdict = row.get("your_verdict(correct/incorrect)", "").strip().lower()
            if verdict in ("correct", "c", "yes", "y", "1"):
                correct += 1
            elif verdict in ("incorrect", "i", "no", "n", "0"):
                incorrect += 1
            else:
                unmarked += 1

    print("=" * 50)
    print("MANUAL LABEL VERIFICATION RESULTS")
    print("=" * 50)
    print(f"  Total sampled:  {total}")
    print(f"  Correct labels: {correct}")
    print(f"  Incorrect:      {incorrect}")
    print(f"  Unmarked:       {unmarked}")
    if total - unmarked > 0:
        accuracy = correct / (total - unmarked) * 100
        print(f"\n  Label accuracy: {accuracy:.1f}%")
        print(f"\n  (This number goes directly into your thesis)")
    print("=" * 50)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", action="store_true", help="Generate CSV for labeling")
    parser.add_argument("--evaluate", action="store_true", help="Compute accuracy from labeled CSV")
    args = parser.parse_args()

    if args.evaluate:
        evaluate()
    else:
        sample_and_export()


if __name__ == "__main__":
    main()
