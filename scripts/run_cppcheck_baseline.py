# [传统工具基线] 在测试集上运行Cppcheck 2.20，计算F1作为传统静态工具对比基线
#!/usr/bin/env python3
"""Cppcheck static analyzer baseline.

Runs Cppcheck on each test sample as a traditional static analysis baseline.
Demonstrates that rule-based tools fail on function-level code snippets
(missing compilation context, headers, etc.) - motivating our LLM-based approach.

Usage:
    python scripts/run_cppcheck_baseline.py
    python scripts/run_cppcheck_baseline.py --cppcheck-path "C:/Program Files/Cppcheck/cppcheck.exe"
"""

import argparse
import json
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent

# Common cppcheck search paths
DEFAULT_PATHS = [
    "cppcheck",
    "C:/Program Files/Cppcheck/cppcheck.exe",
    "C:/Program Files (x86)/Cppcheck/cppcheck.exe",
]

# CWE id mapping from cppcheck error IDs
CPPCHECK_CWE_MAP = {
    "nullPointer": "CWE-476",
    "nullPointerRedundantCheck": "CWE-476",
    "possibleNullPointerArithmetic": "CWE-476",
    "bufferOverflow": "CWE-119",
    "bufferAccessOutOfBounds": "CWE-119",
    "outOfBounds": "CWE-119",
    "stringLiteralWritten": "CWE-119",
    "arrayIndexOutOfBounds": "CWE-119",
    "memleakOnRealloc": "CWE-401",
    "memleak": "CWE-401",
    "resourceLeak": "CWE-401",
    "doubleFree": "CWE-416",
    "deallocDealloc": "CWE-416",
    "danglingPointer": "CWE-416",
    "integerOverflow": "CWE-190",
    "signedIntegerOverflow": "CWE-190",
    "unsignedLessThanZero": "CWE-190",
}

SEVERITY_MAP = {
    "error": True,
    "warning": True,
    "performance": False,
    "portability": False,
    "information": False,
    "style": False,
}


def find_cppcheck(override: Optional[str] = None) -> Optional[str]:
    if override:
        return override if Path(override).exists() else None
    for path in DEFAULT_PATHS:
        try:
            result = subprocess.run(
                [path, "--version"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return path
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
    return None


def run_cppcheck_on_snippet(
    code: str,
    language: str,
    cppcheck_path: str,
    timeout: int = 15,
) -> Tuple[bool, List[Dict]]:
    """Run cppcheck on a code snippet. Returns (has_issue, issues_list)."""
    if language == "Python":
        return False, []

    ext = ".cpp" if language == "C++" else ".c"

    with tempfile.NamedTemporaryFile(mode="w", suffix=ext,
                                     delete=False, encoding="utf-8") as f:
        f.write(code)
        tmp_path = f.name

    try:
        cmd = [
            cppcheck_path,
            "--enable=all",
            "--xml",
            "--xml-version=2",
            "--suppress=missingInclude",
            "--suppress=missingIncludeSystem",
            "--suppress=unmatchedSuppression",
            "--suppress=unusedFunction",
            "--suppress=checkLibraryFunction",
            "--suppress=unknownMacro",
            "--suppress=preprocessorErrorDirective",
            "--inline-suppr",
            tmp_path,
        ]
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, errors="replace",
        )
        # cppcheck writes XML to stderr
        xml_output = proc.stderr

        issues = []
        try:
            root = ET.fromstring(xml_output) if xml_output.strip() else None
            if root is not None:
                for error in root.findall(".//error"):
                    error_id = error.get("id", "")
                    severity = error.get("severity", "")
                    msg = error.get("msg", "")
                    cwe = error.get("cwe", "")

                    if not SEVERITY_MAP.get(severity, False):
                        continue
                    if error_id in ("noValidConfiguration",):
                        continue

                    issues.append({
                        "id": error_id,
                        "severity": severity,
                        "msg": msg,
                        "cwe_mapped": CPPCHECK_CWE_MAP.get(error_id),
                        "cwe_reported": f"CWE-{cwe}" if cwe else None,
                    })
        except ET.ParseError:
            pass

        has_issue = len(issues) > 0
        return has_issue, issues

    except subprocess.TimeoutExpired:
        return False, [{"id": "timeout", "severity": "info", "msg": "Cppcheck timed out"}]
    except Exception as e:
        return False, [{"id": "error", "severity": "info", "msg": str(e)}]
    finally:
        try:
            Path(tmp_path).unlink()
        except Exception:
            pass


def load_jsonl(path: Path) -> List[dict]:
    samples = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def compute_metrics(predictions: List[dict]) -> Dict:
    tp = fp = tn = fn = 0
    for p in predictions:
        pred = p["predicted_vuln"]
        true = p["true_label"] == 1
        if pred and true: tp += 1
        elif pred and not true: fp += 1
        elif not pred and not true: tn += 1
        else: fn += 1
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    return {
        "total": total, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round((tp + tn) / total, 4) if total else 0,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", type=str, default="data/test_v2_filtered.jsonl")
    parser.add_argument("--cppcheck-path", type=str, default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--output", type=str,
                        default="experiments/eval_cppcheck_baseline.json")
    args = parser.parse_args()

    cppcheck = find_cppcheck(args.cppcheck_path)
    if not cppcheck:
        print("ERROR: cppcheck not found. Install it or pass --cppcheck-path")
        print("  winget install cppcheck")
        sys.exit(1)

    print(f"Using cppcheck: {cppcheck}")
    result = subprocess.run([cppcheck, "--version"],
                           capture_output=True, text=True)
    print(f"Version: {result.stdout.strip()}")

    test_path = ROOT / args.test
    samples = load_jsonl(test_path)
    if args.limit:
        samples = samples[:args.limit]
    print(f"Running on {len(samples)} samples...")

    predictions = []
    cpp_count = py_count = skip_count = 0

    for i, sample in enumerate(samples):
        sample_id = sample.get("id", f"s{i}")
        code = sample.get("vulnerable_code", "") or sample.get("code", "")
        language = sample.get("language", "C++")
        true_label = sample.get("label", 0)
        true_cwe = sample.get("cwe_id")

        if not code:
            skip_count += 1
            pred_vuln = False
            issues = []
        elif language == "Python":
            py_count += 1
            pred_vuln = False
            issues = []
        else:
            cpp_count += 1
            pred_vuln, issues = run_cppcheck_on_snippet(code, language, cppcheck)

        predictions.append({
            "sample_id": sample_id,
            "true_label": true_label,
            "true_cwe": true_cwe,
            "predicted_vuln": pred_vuln,
            "language": language,
            "issues_count": len(issues),
            "issues": issues[:3],
        })

        if (i + 1) % 10 == 0 or i == len(samples) - 1:
            m = compute_metrics(predictions)
            print(f"  [{i+1}/{len(samples)}] "
                  f"P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f}")

    metrics = compute_metrics(predictions)
    cwe_recall = {}
    for p in predictions:
        cwe = p.get("true_cwe")
        if p["true_label"] == 1 and cwe:
            if cwe not in cwe_recall:
                cwe_recall[cwe] = {"total": 0, "detected": 0}
            cwe_recall[cwe]["total"] += 1
            if p["predicted_vuln"]:
                cwe_recall[cwe]["detected"] += 1
    for c in cwe_recall:
        d = cwe_recall[c]
        d["recall"] = round(d["detected"] / d["total"], 4) if d["total"] else 0

    output = {
        "tool": "Cppcheck",
        "version": result.stdout.strip(),
        "samples": len(predictions),
        "cpp_analyzed": cpp_count,
        "python_skipped": py_count,
        "metrics": metrics,
        "cwe_recall": cwe_recall,
        "predictions": predictions,
    }
    out_path = ROOT / args.output
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\n" + "=" * 60)
    print("CPPCHECK BASELINE RESULTS")
    print("=" * 60)
    print(f"  Samples: {metrics['total']} ({cpp_count} C++, {py_count} Python skipped)")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1:        {metrics['f1']:.4f}")
    print(f"  Confusion: TP={metrics['tp']} FP={metrics['fp']} TN={metrics['tn']} FN={metrics['fn']}")
    print(f"\nPer-CWE recall:")
    for cwe, d in sorted(cwe_recall.items()):
        print(f"  {cwe}: {d['detected']}/{d['total']} = {d['recall']:.2f}")
    print(f"\nSaved to: {out_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
