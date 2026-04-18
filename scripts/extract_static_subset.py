import argparse
import ast
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.evaluate_rag_vs_norag import DATASET_PATH, load_jsonl  # noqa: E402


CPP_FUNCTION_RE = re.compile(
    r"^\s*(?:template\s*<[^>]+>\s*)?(?:[\w:&*<>\[\],~]+\s+)+[\w:~]+\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:\n\s*)?\{",
    re.MULTILINE,
)
PYTHON_FUNCTION_RE = re.compile(r"^\s*def\s+\w+\s*\([^)]*\)\s*:\s*(?:#.*)?$", re.MULTILINE)
CPP_DECLARATION_RE = re.compile(r"^\s*(?:[\w:&*<>\[\],~]+\s+)+[\w:~]+\s*\([^;{}]*\)\s*;\s*$", re.MULTILINE)
NOISE_RE = re.compile(r"^\s*(?:NOTE:|@param\b|@type\b|来自\s)", re.MULTILINE)
ACCESS_SPECIFIER_RE = re.compile(r"^\s*(?:public|private|protected)\s*:\s*$", re.MULTILINE)
CLASS_RE = re.compile(r"^\s*(?:class|struct)\b", re.MULTILINE)
CPP_BLOCK_START_RE = re.compile(r"^(?:\{|if\b|for\b|while\b|switch\b|try\b|do\b|else\b)")


def brace_balance(code: str) -> int:
    return code.count("{") - code.count("}")


def paren_balance(code: str) -> int:
    return code.count("(") - code.count(")")


def cleaned_lines(code: str) -> List[str]:
    return [line.rstrip() for line in code.splitlines() if line.strip()]


def substantive_lines(code: str) -> List[str]:
    lines: List[str] = []
    for line in code.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("//") or stripped in {"/*", "*/"} or stripped.startswith("*"):
            continue
        lines.append(stripped)
    return lines


def classify_sample(code: str, language: str) -> Tuple[bool, str, Dict[str, int]]:
    lines = cleaned_lines(code)
    core_lines = substantive_lines(code)
    metrics = {
        "line_count": len(lines),
        "char_count": len(code.strip()),
        "brace_balance": brace_balance(code),
        "paren_balance": paren_balance(code),
        "semicolon_count": code.count(";"),
    }
    raw = code.strip()
    lang = (language or "").strip().lower()

    if not raw:
        return False, "empty", metrics
    if len(lines) < 4:
        return False, "too_short", metrics
    if NOISE_RE.search(raw):
        return False, "contains_noise_text", metrics
    if metrics["paren_balance"] != 0:
        return False, "unbalanced_parentheses", metrics

    if "python" in lang:
        try:
            ast.parse(raw)
        except SyntaxError:
            return False, "python_syntax_error", metrics
        first_line = core_lines[0] if core_lines else ""
        if first_line.startswith("def ") and PYTHON_FUNCTION_RE.search(raw) and len(lines) >= 4:
            return True, "python_function", metrics
        if len(lines) >= 8 and first_line.startswith(("if ", "for ", "while ", "try:", "with ", "class ")):
            return True, "python_block", metrics
        return False, "python_fragment", metrics

    first_line = core_lines[0] if core_lines else ""
    if CPP_DECLARATION_RE.search(raw) and "{" not in raw:
        return False, "cpp_declaration", metrics
    if first_line.startswith(("class ", "struct ")):
        return False, "cpp_class_fragment", metrics
    if ACCESS_SPECIFIER_RE.search(raw) and not CLASS_RE.search(raw):
        return False, "cpp_class_fragment", metrics
    lead = "\n".join(core_lines[:3])
    if CPP_FUNCTION_RE.search(lead) and metrics["brace_balance"] == 0 and len(lines) >= 5 and raw.endswith("}"):
        return True, "cpp_function", metrics
    if (
        "{" in raw
        and "}" in raw
        and metrics["brace_balance"] == 0
        and len(lines) >= 8
        and metrics["semicolon_count"] >= 2
        and CPP_BLOCK_START_RE.search(first_line)
        and raw.endswith("}")
    ):
        return True, "cpp_block", metrics
    return False, "cpp_fragment", metrics


def dump_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract dataset samples suitable for static analysis")
    parser.add_argument("--dataset", type=str, default=str(DATASET_PATH), help="Input dataset JSONL path")
    parser.add_argument(
        "--output",
        type=str,
        default="data/static_analysis/dataset_static_subset.jsonl",
        help="Output JSONL path",
    )
    parser.add_argument(
        "--summary-output",
        type=str,
        default="experiments/static_subset_summary.json",
        help="Summary JSON path",
    )
    args = parser.parse_args()

    dataset_path = ROOT / args.dataset if not Path(args.dataset).is_absolute() else Path(args.dataset)
    output_path = ROOT / args.output if not Path(args.output).is_absolute() else Path(args.output)
    summary_path = ROOT / args.summary_output if not Path(args.summary_output).is_absolute() else Path(args.summary_output)

    dataset = load_jsonl(dataset_path)
    selected: List[Dict[str, Any]] = []
    accepted_by_lang: Dict[str, int] = defaultdict(int)
    accepted_by_type: Counter[str] = Counter()
    rejected_by_reason: Counter[str] = Counter()

    for sample in dataset:
        code = sample.get("vulnerable_code", "")
        language = sample.get("language", "unknown")
        ok, sample_type, metrics = classify_sample(code, language)
        if ok:
            enriched = dict(sample)
            enriched["static_subset_type"] = sample_type
            enriched["static_subset_metrics"] = metrics
            selected.append(enriched)
            accepted_by_lang[language] += 1
            accepted_by_type[sample_type] += 1
        else:
            rejected_by_reason[sample_type] += 1

    dump_jsonl(output_path, selected)

    summary = {
        "dataset": str(dataset_path),
        "total_samples": len(dataset),
        "selected_samples": len(selected),
        "selection_ratio": round(len(selected) / len(dataset), 4) if dataset else 0.0,
        "accepted_by_language": dict(sorted(accepted_by_lang.items())),
        "accepted_by_type": dict(accepted_by_type),
        "rejected_by_reason": dict(rejected_by_reason),
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("=" * 72)
    print("Static-analysis subset extraction")
    print("=" * 72)
    print(f"输入样本数: {len(dataset)}")
    print(f"筛出样本数: {len(selected)}")
    print(f"保留比例: {summary['selection_ratio']:.2%}")
    print("按语言保留:")
    for language, count in sorted(accepted_by_lang.items()):
        print(f"  {language:<10} {count}")
    print("按类型保留:")
    for sample_type, count in accepted_by_type.most_common():
        print(f"  {sample_type:<16} {count}")
    print("主要拒绝原因:")
    for reason, count in rejected_by_reason.most_common(6):
        print(f"  {reason:<20} {count}")
    print(f"\n子集已保存到: {output_path}")
    print(f"摘要已保存到: {summary_path}")


if __name__ == "__main__":
    main()
