import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple
from xml.etree import ElementTree as ET


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.evaluate_rag_vs_norag import DATASET_PATH, compute_metrics, load_jsonl  # noqa: E402


CPP_EXTENSIONS = {"c": ".c", "cc": ".cc", "cpp": ".cpp", "c++": ".cpp", "cxx": ".cpp", "hpp": ".hpp", "h": ".h"}
PY_EXTENSIONS = {"python": ".py", "py": ".py"}

CPPSECURITY_RE = re.compile(
    r"(overflow|out.?of.?bounds|null|dangling|use.?after.?free|double.?free|leak|"
    r"race|deadlock|division by zero|zerodiv|buffer|arrayindex|memleak|format|string|"
    r"uninit|command|inject|overflow)",
    re.IGNORECASE,
)
CPP_NOISE_IDS = {
    "missingInclude",
    "missingIncludeSystem",
    "checkersReport",
    "unmatchedSuppression",
    "toomanyconfigs",
    "syntaxError",
    "noValidConfiguration",
}


def cppcheck_candidate_sources(code: str) -> List[str]:
    raw = (code or "").strip()
    wrapped = (
        "#include <cstdint>\n"
        "#include <cstdio>\n"
        "#include <cstdlib>\n"
        "#include <cstring>\n"
        "#include <memory>\n"
        "#include <string>\n"
        "#include <vector>\n"
        "#include <map>\n"
        "using namespace std;\n"
        "void __cursor_snippet__() {\n"
        f"{code}\n"
        "}\n"
    ).strip()
    return [raw, wrapped] if raw != wrapped else [raw]


def run_cppcheck(code: str) -> List[str]:
    findings: List[str] = []
    with tempfile.TemporaryDirectory() as tmpdir:
        for idx, candidate in enumerate(cppcheck_candidate_sources(code), 1):
            path = Path(tmpdir) / f"snippet_{idx}.cpp"
            path.write_text(candidate, encoding="utf-8")
            proc = subprocess.run(
                [
                    "cppcheck",
                    "--enable=all",
                    "--inconclusive",
                    "--force",
                    "--language=c++",
                    "--xml",
                    "--xml-version=2",
                    str(path),
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            xml_text = (proc.stderr or "").strip()
            if not xml_text:
                continue
            try:
                root = ET.fromstring(xml_text)
            except ET.ParseError:
                continue
            candidate_hits: List[str] = []
            for err in root.findall(".//error"):
                issue_id = err.attrib.get("id", "")
                severity = err.attrib.get("severity", "")
                message = err.attrib.get("msg", "")
                if issue_id in CPP_NOISE_IDS:
                    continue
                searchable = f"{issue_id} {severity} {message}"
                if severity == "error" or CPPSECURITY_RE.search(searchable):
                    candidate_hits.append(f"cppcheck:{issue_id}:{severity}")
            if len(candidate_hits) > len(findings):
                findings = candidate_hits
    return findings


def detect_extension(language: str) -> str:
    lang = (language or "").strip().lower()
    if lang in PY_EXTENSIONS:
        return PY_EXTENSIONS[lang]
    return CPP_EXTENSIONS.get(lang, ".cpp")


def run_semgrep(code: str, language: str) -> List[str]:
    with tempfile.TemporaryDirectory() as tmpdir:
        ext = detect_extension(language)
        path = Path(tmpdir) / f"snippet{ext}"
        path.write_text(code or "", encoding="utf-8")
        proc = subprocess.run(
            [
                "semgrep",
                "scan",
                "--config",
                "auto",
                "--json",
                "--quiet",
                "--metrics=off",
                str(path),
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )
        stdout = (proc.stdout or "").strip()
        if not stdout:
            return []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return []
        findings: List[str] = []
        for item in data.get("results", []):
            check_id = item.get("check_id", "semgrep.unknown")
            extra = item.get("extra", {})
            severity = str(extra.get("severity", "INFO")).upper()
            message = str(extra.get("message", ""))
            searchable = f"{check_id} {severity} {message}"
            if severity in {"ERROR", "WARNING"} or CPPSECURITY_RE.search(searchable):
                findings.append(f"semgrep:{check_id}:{severity}")
        return findings


def static_tool_predict(code: str, language: str) -> Tuple[int, float, List[str]]:
    lang = (language or "").strip().lower()
    findings: List[str] = []

    if "python" in lang or lang == "py":
        findings.extend(run_semgrep(code, language))
    else:
        findings.extend(run_cppcheck(code))
        findings.extend(run_semgrep(code, language))

    deduped = sorted(set(findings))
    if deduped:
        confidence = min(0.68 + 0.06 * len(deduped), 0.95)
        return 1, confidence, deduped
    return 0, 0.55, []


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate stronger static tools baseline")
    parser.add_argument("--dataset", type=str, default=str(DATASET_PATH), help="Dataset JSONL path")
    parser.add_argument(
        "--output",
        type=str,
        default="experiments/static_tools_advanced_result.json",
        help="Output JSON path",
    )
    parser.add_argument("--limit", type=int, default=0, help="Only evaluate first N samples")
    args = parser.parse_args()

    dataset_path = ROOT / args.dataset if not Path(args.dataset).is_absolute() else Path(args.dataset)
    output_path = ROOT / args.output if not Path(args.output).is_absolute() else Path(args.output)
    dataset_all = load_jsonl(dataset_path)
    dataset = dataset_all[: args.limit] if args.limit and args.limit > 0 else dataset_all

    print("=" * 72)
    print("RoboGuard Advanced Static Tools Baseline")
    print("Tools: Cppcheck + Semgrep")
    print("=" * 72)
    print(f"样本数: {len(dataset)}")

    true_labels: List[int] = []
    preds: List[int] = []
    confidences: List[float] = []
    rows: List[Dict[str, Any]] = []

    for idx, sample in enumerate(dataset, 1):
        code = sample.get("vulnerable_code", "")
        language = sample.get("language", "unknown")
        label = int(sample.get("label", 0))
        sample_id = sample.get("id", f"sample_{idx}")

        pred, conf, hits = static_tool_predict(code, language)
        true_labels.append(label)
        preds.append(pred)
        confidences.append(conf)

        print(
            f"[{idx:>3}/{len(dataset)}] {sample_id} | lang={language:<6} "
            f"| true={label} pred={pred} conf={conf:.2f} hits={hits[:3]}"
        )

        rows.append(
            {
                "id": sample_id,
                "language": language,
                "true_label": label,
                "pred": pred,
                "confidence": conf,
                "tool_hits": hits,
            }
        )

    overall = compute_metrics(true_labels, preds)
    overall["avg_confidence"] = sum(confidences) / len(confidences) if confidences else 0.0

    output = {
        "config": {
            "dataset": str(dataset_path),
            "sample_size": len(dataset),
            "tools": ["cppcheck", "semgrep"],
        },
        "overall": overall,
        "samples": rows,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print("\n" + "-" * 60)
    print(
        f"overall -> f1={overall['f1']:.4f} acc={overall['accuracy']:.4f} "
        f"prec={overall['precision']:.4f} rec={overall['recall']:.4f}"
    )
    print("-" * 60)
    print(f"结果已保存到: {output_path}")


if __name__ == "__main__":
    main()
