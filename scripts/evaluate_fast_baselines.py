import argparse
import json
import random
import re
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Tuple

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

load_dotenv(ROOT / ".env")

from scripts.evaluate_rag_vs_norag import (  # noqa: E402
    API_KEY,
    CORPUS_PATH,
    DATASET_PATH,
    REQUEST_INTERVAL,
    TOP_K,
    build_bm25,
    build_dense_index,
    build_no_rag_messages,
    build_rag_messages,
    build_tfidf,
    call_qwen,
    compute_metrics,
    hybrid_retrieve,
    load_jsonl,
    parse_label,
)


GENERIC_CWE_DOCS: List[Dict[str, Any]] = [
    {
        "id": "generic-cwe-119",
        "type": "generic_security_rule",
        "content": (
            "CWE-119 Buffer Overflow / Out-of-bounds write: dangerous signals include memcpy, strcpy, "
            "sprintf, gets, unchecked buffer sizes, and writing based on external length values. "
            "Recommended fixes: explicit bounds checks, safer APIs, and validating destination capacity."
        ),
        "metadata": {"cwe_id": "CWE-119"},
    },
    {
        "id": "generic-cwe-125",
        "type": "generic_security_rule",
        "content": (
            "CWE-125 Out-of-bounds Read: risky patterns include direct array or vector indexing without "
            "range validation. Recommended fixes: validate indices and lengths before access."
        ),
        "metadata": {"cwe_id": "CWE-125"},
    },
    {
        "id": "generic-cwe-134",
        "type": "generic_security_rule",
        "content": (
            "CWE-134 Format String Vulnerability: avoid passing attacker-controlled strings as printf-like "
            "format arguments. Use fixed format strings such as printf('%s', msg) instead."
        ),
        "metadata": {"cwe_id": "CWE-134"},
    },
    {
        "id": "generic-cwe-190",
        "type": "generic_security_rule",
        "content": (
            "CWE-190 Integer Overflow: high risk when multiplying sizes, converting lengths, or computing "
            "offsets without overflow checks. Recommended fixes: checked arithmetic and upper-bound validation."
        ),
        "metadata": {"cwe_id": "CWE-190"},
    },
    {
        "id": "generic-cwe-362",
        "type": "generic_security_rule",
        "content": (
            "CWE-362 Race Condition: shared state updated from callbacks, threads, timers, or async handlers "
            "without locks may cause inconsistent behavior. Recommended fixes: mutexes, atomics, and reduced "
            "shared mutable state."
        ),
        "metadata": {"cwe_id": "CWE-362"},
    },
    {
        "id": "generic-cwe-367",
        "type": "generic_security_rule",
        "content": (
            "CWE-367 TOCTOU Race Condition: checking file access or existence and then using the file later "
            "can be unsafe. Prefer directly opening or operating on the resource and handling errors."
        ),
        "metadata": {"cwe_id": "CWE-367"},
    },
    {
        "id": "generic-cwe-369",
        "type": "generic_security_rule",
        "content": (
            "CWE-369 Divide By Zero: divisions by dt, count, width, or other runtime values need zero checks "
            "before arithmetic."
        ),
        "metadata": {"cwe_id": "CWE-369"},
    },
    {
        "id": "generic-cwe-401",
        "type": "generic_security_rule",
        "content": (
            "CWE-401 Memory Leak: repeated allocation with new or malloc without release causes resource leaks. "
            "Recommended fixes: RAII, smart pointers, clear ownership, and cleanup on error paths."
        ),
        "metadata": {"cwe_id": "CWE-401"},
    },
    {
        "id": "generic-cwe-416",
        "type": "generic_security_rule",
        "content": (
            "CWE-416 Use After Free: dereferencing pointers or objects after delete/free is critical. "
            "Recommended fixes: clear ownership, set pointers to null after release, and avoid manual lifetime bugs."
        ),
        "metadata": {"cwe_id": "CWE-416"},
    },
    {
        "id": "generic-cwe-476",
        "type": "generic_security_rule",
        "content": (
            "CWE-476 Null Pointer Dereference: check pointers, shared pointers, or object fields before dereference, "
            "especially on error paths or optional values."
        ),
        "metadata": {"cwe_id": "CWE-476"},
    },
    {
        "id": "generic-cwe-78",
        "type": "generic_security_rule",
        "content": (
            "CWE-78 Command Injection: avoid building shell commands by concatenating user input into os.system, "
            "subprocess with shell=True, or similar APIs. Use argument lists and input validation."
        ),
        "metadata": {"cwe_id": "CWE-78"},
    },
    {
        "id": "generic-cwe-89",
        "type": "generic_security_rule",
        "content": (
            "CWE-89 SQL Injection: do not concatenate user input into SQL strings. Use parameterized queries or "
            "prepared statements."
        ),
        "metadata": {"cwe_id": "CWE-89"},
    },
    {
        "id": "generic-safe-patterns",
        "type": "generic_safe_rule",
        "content": (
            "Safe coding patterns: use std::shared_ptr or std::unique_ptr for ownership, validate external inputs, "
            "use mutexes for shared mutable state, prefer fixed format strings, and return errors instead of "
            "continuing after invalid state."
        ),
        "metadata": {"is_safe_pattern": True},
    },
]

CPP_EXTENSIONS = {"c", "cc", "cpp", "cxx", "hpp", "hxx", "h"}
PYTHON_EXTENSIONS = {"py"}
CPPSECURITY_RE = re.compile(
    r"(overflow|outofbounds|out of bounds|null|dangling|use.?after.?free|double.?free|"
    r"leak|resource|buffer|arrayIndex|zerodiv|divide|format|string|uninit|unassigned|"
    r"invalidPrintf|memleak|dealloc|deference|nullptr)",
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

FEW_SHOT_PICK_IDS = [
    "ros_comm_CVE-2023-12345_001",
    "ros2_rclcpp_race_004",
    "ros_comm_cmdinj_011",
    "image_transport_benign_009",
    "actionlib_benign_010",
]

FEW_SHOT_SYSTEM_PROMPT = """你是一名资深代码安全审查工程师。请分析给定代码是否存在安全漏洞。

请以如下JSON格式输出（只输出JSON，不要有其他内容）：
{
  "label": 1,
  "vuln_type": "漏洞类型，若无则填null",
  "confidence": 0.85,
  "reasoning": "简要说明判断依据"
}

其中：
- label: 1表示存在漏洞，0表示无漏洞
- confidence: 你对判断结果的置信度（0.0~1.0）
"""

GENERIC_RAG_SYSTEM_PROMPT = """你是一名代码安全专家。你会收到通用安全知识库文档（CWE模式、修复建议、安全编码规则）。
请结合这些通用安全知识来分析代码是否存在安全漏洞，不要依赖机器人或ROS特定知识。

请以如下JSON格式输出（只输出JSON，不要有其他内容）：
{
  "label": 1,
  "vuln_type": "漏洞类型，若无则填null",
  "confidence": 0.85,
  "reasoning": "简要说明判断依据，并引用参考文档编号"
}
"""


def extract_confidence(response: str) -> float:
    try:
        parsed = json.loads(response.strip())
        return float(parsed.get("confidence", 0.5))
    except Exception:
        match = re.search(r'"confidence"\s*:\s*([\d.]+)', response)
        return float(match.group(1)) if match else 0.5


def _cppcheck_candidate_sources(code: str) -> List[str]:
    raw = code.strip()
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
    candidates = [raw]
    if raw != wrapped:
        candidates.append(wrapped)
    return candidates


def _run_cppcheck(code: str) -> List[str]:
    findings: List[str] = []
    with tempfile.TemporaryDirectory() as tmpdir:
        for idx, candidate in enumerate(_cppcheck_candidate_sources(code), 1):
            path = Path(tmpdir) / f"snippet_{idx}.cpp"
            path.write_text(candidate, encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
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
                timeout=45,
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


def _run_bandit(code: str) -> List[str]:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "snippet.py"
        path.write_text(code, encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, "-m", "bandit", "-q", "-f", "json", str(path)],
            capture_output=True,
            text=True,
            timeout=45,
        )
        stdout = (proc.stdout or "").strip()
        if not stdout:
            return []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return []
        findings = []
        for item in data.get("results", []):
            severity = str(item.get("issue_severity", "LOW")).upper()
            confidence = str(item.get("issue_confidence", "LOW")).upper()
            test_id = item.get("test_id", "UNKNOWN")
            if severity in {"MEDIUM", "HIGH"} or confidence == "HIGH":
                findings.append(f"bandit:{test_id}:{severity}")
        return findings


def static_tool_predict(code: str, language: str) -> Tuple[int, float, List[str]]:
    lang = (language or "").strip().lower()
    findings: List[str] = []

    if "python" in lang or lang in PYTHON_EXTENSIONS:
        findings = _run_bandit(code)
    else:
        findings = _run_cppcheck(code)

    if findings:
        confidence = min(0.68 + 0.07 * len(findings), 0.95)
        return 1, confidence, findings
    return 0, 0.55, []


def sample_balanced(dataset_all: List[Dict[str, Any]], sample_size: int, seed: int) -> List[Dict[str, Any]]:
    random.seed(seed)
    vuln = [s for s in dataset_all if s.get("label") == 1]
    safe = [s for s in dataset_all if s.get("label") == 0]
    half = max(sample_size // 2, 1)
    chosen_vuln = random.sample(vuln, min(half, len(vuln)))
    chosen_safe = random.sample(safe, min(half, len(safe)))
    sampled = chosen_vuln + chosen_safe
    random.shuffle(sampled)
    return sampled


def build_few_shot_block() -> str:
    sample_path = ROOT / "data" / "demos" / "dataset_sample.jsonl"
    examples = load_jsonl(sample_path)
    picked = {item["id"]: item for item in examples if item.get("id") in FEW_SHOT_PICK_IDS}
    ordered = [picked[item_id] for item_id in FEW_SHOT_PICK_IDS if item_id in picked]

    blocks = []
    for i, ex in enumerate(ordered, 1):
        blocks.append(
            f"示例{i}:\n"
            f"代码:\n```{ex.get('language', '').lower() or 'text'}\n{ex.get('vulnerable_code', '')}\n```\n"
            f"答案:\n"
            f'{{"label": {ex.get("label", 0)}, "vuln_type": {json.dumps(ex.get("cwe_name"), ensure_ascii=False)}, '
            f'"confidence": 0.95, "reasoning": {json.dumps(ex.get("description", ""), ensure_ascii=False)}}}'
        )
    return "\n\n".join(blocks)


def build_few_shot_messages(code: str, examples_block: str) -> List[Dict[str, str]]:
    return [
        {"role": "system", "content": FEW_SHOT_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                "下面给出若干安全分析示例，请学习它们的判断方式。\n\n"
                f"{examples_block}\n\n"
                "---\n\n"
                f"现在请分析以下代码：\n\n```cpp\n{code}\n```"
            ),
        },
    ]


def build_generic_rag_messages(code: str, retrieved_docs: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    context_parts = []
    for i, doc in enumerate(retrieved_docs, 1):
        context_parts.append(f"[参考文档{i}] (id={doc['id']})\n{doc['content']}")
    context = "\n\n".join(context_parts)
    return [
        {"role": "system", "content": GENERIC_RAG_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"以下是通用安全知识库中检索到的文档：\n\n{context}\n\n"
                f"---\n\n请分析以下代码：\n\n```\n{code}\n```"
            ),
        },
    ]


def prepare_retrieval(corpus: List[Dict[str, Any]]) -> Tuple:
    texts = [doc.get("content", "") for doc in corpus]
    bm25_index = build_bm25(texts)
    vocab_idx, idf_vals, tfidf_matrix = build_tfidf(texts)
    dense_model, dense_emb = build_dense_index(texts)
    return bm25_index, vocab_idx, idf_vals, tfidf_matrix, dense_model, dense_emb


def retrieve_docs(
    code: str,
    corpus: List[Dict[str, Any]],
    retrieval_bundle: Tuple,
    top_k: int = TOP_K,
) -> List[Dict[str, Any]]:
    bm25_index, vocab_idx, idf_vals, tfidf_matrix, dense_model, dense_emb = retrieval_bundle
    retrieved, _debug = hybrid_retrieve(
        code,
        corpus,
        vocab_idx,
        idf_vals,
        tfidf_matrix,
        bm25_index,
        dense_model=dense_model,
        dense_corpus_emb=dense_emb,
        top_k=top_k,
        use_reranker=False,
        use_dynamic_topk=False,
    )
    return [corpus[idx] for idx, _score in retrieved]


def evaluate_method(messages: List[Dict[str, str]]) -> Tuple[int, float, str]:
    response = call_qwen(messages)
    return parse_label(response), extract_confidence(response), response


def main() -> None:
    parser = argparse.ArgumentParser(description="Fast teacher-demo baselines for RoboGuard")
    parser.add_argument("--sample-size", type=int, default=12, help="Balanced sample size from dataset_full")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--request-interval", type=float, default=max(0.5, REQUEST_INTERVAL), help="Sleep between API calls")
    parser.add_argument("--output", type=str, default="experiments/fast_baselines_result.json", help="Output JSON path")
    args = parser.parse_args()

    if not API_KEY:
        print("[ERROR] DASHSCOPE_API_KEY 未配置，无法调用模型。")
        return

    dataset_all = load_jsonl(DATASET_PATH)
    robotics_corpus = load_jsonl(CORPUS_PATH)
    generic_corpus = GENERIC_CWE_DOCS
    dataset = sample_balanced(dataset_all, args.sample_size, args.seed)
    few_shot_examples = build_few_shot_block()

    print("=" * 72)
    print("RoboGuard Fast Baselines")
    print("Methods: static_tools | no_rag | few_shot | generic_security_rag | robotics_rag")
    print("=" * 72)
    print(f"样本数: {len(dataset)}")
    print(f"机器人知识库文档数: {len(robotics_corpus)}")
    print(f"通用安全知识库文档数: {len(generic_corpus)}")

    print("\n[1/3] 构建检索索引...")
    robotics_bundle = prepare_retrieval(robotics_corpus)
    generic_bundle = prepare_retrieval(generic_corpus)

    method_order = ["static_tools", "no_rag", "few_shot", "generic_rag", "robotics_rag"]
    method_labels = {
        "static_tools": "Cppcheck/Bandit",
        "no_rag": "No RAG",
        "few_shot": "Few-shot",
        "generic_rag": "Generic Security RAG",
        "robotics_rag": "Robotics RAG",
    }
    preds: Dict[str, List[int]] = {name: [] for name in method_order}
    confs: Dict[str, List[float]] = {name: [] for name in method_order}
    sample_rows: List[Dict[str, Any]] = []
    true_labels: List[int] = []

    print("\n[2/3] 开始推理...")
    for i, sample in enumerate(dataset, 1):
        code = sample.get("vulnerable_code", "")
        language = sample.get("language", "")
        label = int(sample.get("label", 0))
        sample_id = sample.get("id", f"sample_{i}")
        true_labels.append(label)

        print(f"\n样本 {i}/{len(dataset)}: {sample_id}")
        print(f"真实标签: {label}")

        row: Dict[str, Any] = {"id": sample_id, "true_label": label}

        static_pred, static_conf, static_hits = static_tool_predict(code, language)
        preds["static_tools"].append(static_pred)
        confs["static_tools"].append(static_conf)
        row["static_tools_pred"] = static_pred
        row["static_tool_hits"] = static_hits
        print(f"  Cppcheck/Bandit      -> pred={static_pred} conf={static_conf:.2f} hits={static_hits[:3]}")

        no_rag_pred, no_rag_conf, _ = evaluate_method(build_no_rag_messages(code))
        preds["no_rag"].append(no_rag_pred)
        confs["no_rag"].append(no_rag_conf)
        row["no_rag_pred"] = no_rag_pred
        print(f"  No RAG               -> pred={no_rag_pred} conf={no_rag_conf:.2f}")
        time.sleep(args.request_interval)

        few_shot_pred, few_shot_conf, _ = evaluate_method(build_few_shot_messages(code, few_shot_examples))
        preds["few_shot"].append(few_shot_pred)
        confs["few_shot"].append(few_shot_conf)
        row["few_shot_pred"] = few_shot_pred
        print(f"  Few-shot             -> pred={few_shot_pred} conf={few_shot_conf:.2f}")
        time.sleep(args.request_interval)

        generic_docs = retrieve_docs(code, generic_corpus, generic_bundle, top_k=min(4, len(generic_corpus)))
        generic_pred, generic_conf, _ = evaluate_method(build_generic_rag_messages(code, generic_docs))
        preds["generic_rag"].append(generic_pred)
        confs["generic_rag"].append(generic_conf)
        row["generic_rag_pred"] = generic_pred
        row["generic_doc_ids"] = [doc["id"] for doc in generic_docs]
        print(f"  Generic Security RAG -> pred={generic_pred} conf={generic_conf:.2f}")
        time.sleep(args.request_interval)

        robotics_docs = retrieve_docs(code, robotics_corpus, robotics_bundle, top_k=TOP_K)
        robotics_pred, robotics_conf, _ = evaluate_method(build_rag_messages(code, robotics_docs))
        preds["robotics_rag"].append(robotics_pred)
        confs["robotics_rag"].append(robotics_conf)
        row["robotics_rag_pred"] = robotics_pred
        row["robotics_doc_ids"] = [doc["id"] for doc in robotics_docs]
        print(f"  Robotics RAG         -> pred={robotics_pred} conf={robotics_conf:.2f}")
        time.sleep(args.request_interval)

        sample_rows.append(row)

    print("\n[3/3] 汇总指标...")
    summary: Dict[str, Any] = {
        "config": {
            "sample_size": len(dataset),
            "seed": args.seed,
            "methods": method_order,
        },
        "metrics": {},
        "samples": sample_rows,
    }

    print("\n" + "-" * 60)
    print(f"{'method':<24} {'f1':>8} {'acc':>8} {'prec':>8} {'rec':>8}")
    print("-" * 60)
    for method in method_order:
        metrics = compute_metrics(true_labels, preds[method])
        metrics["avg_confidence"] = sum(confs[method]) / len(confs[method]) if confs[method] else 0.0
        summary["metrics"][method] = metrics
        print(
            f"{method_labels[method]:<24} "
            f"{metrics['f1']:>8.4f} {metrics['accuracy']:>8.4f} "
            f"{metrics['precision']:>8.4f} {metrics['recall']:>8.4f}"
        )

    output_path = ROOT / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("-" * 60)
    print(f"结果已保存到: {output_path}")


if __name__ == "__main__":
    main()
