"""消融实验：有RAG vs 无RAG（使用清理后的数据集，无数据泄漏）

运行前请先重建向量数据库：
    python3 scripts/build_chroma_db.py --reset

运行方式：
    python3 scripts/run_ablation_experiments.py
    python3 scripts/run_ablation_experiments.py --limit 20  # 只跑前20个样本
"""

import argparse
import json
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from dotenv import load_dotenv
import urllib.request
import ssl

# 解决macOS SSL证书问题
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

load_dotenv(ROOT / ".env")

API_KEY = os.getenv("DASHSCOPE_API_KEY", "")
API_BASE = os.getenv("LLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
API_URL = API_BASE + "/chat/completions"


# ── 数据加载 ──

def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    items = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items


def check_overlap(test_data, rag_data) -> float:
    """检查测试集和RAG语料库的ID重叠率"""
    test_ids = set()
    for s in test_data:
        test_ids.add(s.get("id", ""))

    rag_ids = set()
    for s in rag_data:
        # RAG corpus的id可能有hist_前缀
        raw_id = s.get("id", "")
        if raw_id.startswith("hist_"):
            raw_id = raw_id[5:]
        rag_ids.add(raw_id)

    overlap = test_ids & rag_ids
    overlap_rate = len(overlap) / len(test_ids) if test_ids else 0.0
    return overlap_rate


# ── API调用 ──

def call_llm(model: str, messages: List[Dict[str, str]], retries: int = 3) -> str:
    """调用DashScope API"""
    payload = json.dumps({
        "model": model,
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": 1024
    }).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}"
    }

    last_error = ""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(API_URL, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=90, context=ssl_ctx) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            last_error = str(e)
            print(f"    API调用失败(第{attempt+1}次): {e}")
            if attempt < retries - 1:
                time.sleep(5)
    return ""


# ── 标签解析 ──

VULN_KEYWORDS = [
    "存在漏洞", "存在安全漏洞", "发现漏洞", "检测到漏洞",
    "vulnerable", "vulnerability", "buffer overflow", "null pointer",
    "安全问题", "风险", "有漏洞", "该代码有", "该函数有",
    "缓冲区溢出", "空指针", "内存泄漏", "资源泄漏", "并发",
    "label.*:.*1", "\"label\".*1", "is_vulnerable.*true",
]
SAFE_KEYWORDS = [
    "无漏洞", "未发现漏洞", "no vulnerability", "no vulnerabilities",
    "安全", "正常", "没有安全问题", "不存在漏洞",
    "label.*:.*0", "\"label\".*0", "is_vulnerable.*false",
]


def parse_label(response: str) -> int:
    """从模型回复中提取0/1预测标签"""
    text = response.lower()

    # 尝试解析JSON中的label字段
    m = re.search(r'"label"\s*:\s*([01])', text)
    if m:
        return int(m.group(1))
    m = re.search(r'label\s*[=:]\s*([01])', text)
    if m:
        return int(m.group(1))

    # 关键词匹配
    for kw in VULN_KEYWORDS:
        if re.search(kw, text):
            return 1
    for kw in SAFE_KEYWORDS:
        if re.search(kw, text):
            return 0

    # 默认返回1（有漏洞）
    return 1


def extract_confidence(response: str) -> float:
    """提取置信度"""
    try:
        parsed = json.loads(response.strip())
        return float(parsed.get("confidence", 0.5))
    except Exception:
        return 0.5


# ── Prompt构造 ──

SYSTEM_PROMPT_NO_RAG = """你是一名通用C++代码审查工程师，请分析给定的代码片段，判断是否存在安全漏洞。
注意：你对ROS（机器人操作系统）的特定API行为和多线程执行模型了解有限，请基于通用C++安全知识进行判断。

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

SYSTEM_PROMPT_RAG = """你是一名机器人代码安全专家，专注于ROS（机器人操作系统）代码的安全分析。
你会收到相关的漏洞知识库参考文档，请结合这些文档中的模式和修复策略，判断代码是否存在安全漏洞。

重要提示：
- 如果知识库中有与代码高度匹配的漏洞模式，请以此为判断依据
- 如果知识库中有安全用法示例，且代码与之匹配，则代码可能是安全的
- 综合知识库文档和代码特征给出判断

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


def build_no_rag_messages(code: str) -> List[Dict[str, str]]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT_NO_RAG},
        {"role": "user", "content": f"请分析以下代码是否存在安全漏洞：\n\n```cpp\n{code}\n```"}
    ]


def build_rag_messages(code: str, retrieved_docs: list) -> List[Dict[str, str]]:
    context_parts = []
    for i, doc in enumerate(retrieved_docs, 1):
        # LangChain Document对象用属性访问
        doc_content = doc.page_content if hasattr(doc, 'page_content') else str(doc)
        doc_metadata = doc.metadata if hasattr(doc, 'metadata') else {}
        doc_id = doc_metadata.get("id", f"doc_{i}")
        doc_type = doc_metadata.get("type", "unknown")
        context_parts.append(f"[参考文档{i}] (id={doc_id}, type={doc_type})\n{doc_content}")

    context = "\n\n".join(context_parts)

    return [
        {"role": "system", "content": SYSTEM_PROMPT_RAG},
        {
            "role": "user",
            "content": (
                f"以下是从ROS安全知识库中检索到的相关文档：\n\n{context}\n\n"
                f"---\n\n请结合上述知识文档，分析以下代码是否存在安全漏洞：\n\n```\n{code}\n```"
            )
        }
    ]


# ── 指标计算 ──

def compute_metrics(labels: List[int], preds: List[int]) -> Dict[str, float]:
    """计算分类指标"""
    tp = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 1)
    fp = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 1)
    fn = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 0)
    tn = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(labels) if labels else 0.0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn
    }


def compute_per_cwe_metrics(samples: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """按CWE类型计算指标"""
    cwe_groups = defaultdict(lambda: {"labels": [], "preds": []})

    for s in samples:
        cwe = s.get("cwe_id", "unknown")
        label = s.get("true_label", 0)
        pred = s.get("pred", 0)
        cwe_groups[cwe]["labels"].append(label)
        cwe_groups[cwe]["preds"].append(pred)

    per_cwe = {}
    for cwe, data in cwe_groups.items():
        metrics = compute_metrics(data["labels"], data["preds"])
        metrics["sample_count"] = len(data["labels"])
        per_cwe[cwe] = metrics

    return per_cwe


# ── 主流程 ──

def main():
    parser = argparse.ArgumentParser(description="消融实验：有RAG vs 无RAG（清理后数据集）")
    parser.add_argument("--test-dataset", type=str, default="data/test_cleaned.jsonl")
    parser.add_argument("--rag-corpus", type=str, default="data/rag_corpus_cleaned.jsonl")
    parser.add_argument("--model", type=str, default="qwen-plus")
    parser.add_argument("--output-dir", type=str, default="experiments")
    parser.add_argument("--request-interval", type=float, default=2.0)
    parser.add_argument("--limit", type=int, default=0, help="只测试前N个样本（0=全部）")
    args = parser.parse_args()

    if not API_KEY:
        raise RuntimeError("DASHSCOPE_API_KEY 未配置")

    # 加载数据
    test_path = ROOT / args.test_dataset
    rag_path = ROOT / args.rag_corpus
    test_data = load_jsonl(test_path)
    rag_data = load_jsonl(rag_path)

    if args.limit > 0:
        test_data = test_data[:args.limit]

    # 检查数据泄漏
    overlap_rate = check_overlap(test_data, rag_data)
    print("=" * 72)
    print("消融实验：有RAG vs 无RAG（清理后数据集）")
    print("=" * 72)
    print(f"测试集: {test_path} ({len(test_data)} 样本)")
    print(f"RAG语料库: {rag_path} ({len(rag_data)} 样本)")
    print(f"数据泄漏检查: {overlap_rate:.1%} 重叠")
    if overlap_rate > 0.01:
        print("⚠️  警告：测试集和RAG语料库存在重叠，实验结果可能不可信！")
    else:
        print("✅ 数据集独立，无泄漏")
    print()

    # 初始化RAG检索器
    from rag.retriever import RAGRetriever
    rag_retriever = RAGRetriever(persist_dir=str(ROOT / "data/chroma_db"))
    if not rag_retriever.is_ready():
        print("❌ 向量数据库为空，请先运行：")
        print("   python3 scripts/build_chroma_db.py --reset")
        return

    print(f"✅ RAG检索器已加载：{rag_retriever.count()} 个文档")
    print()

    # 运行实验
    no_rag_samples = []
    rag_samples = []

    print("开始实验...")
    print()

    for idx, sample in enumerate(test_data, 1):
        sample_id = sample.get("id", f"sample_{idx}")
        code = sample.get("vulnerable_code", "")
        label = int(sample.get("label", 0))
        cwe_id = sample.get("cwe_id", "unknown")
        language = sample.get("language", "unknown")

        print(f"[{idx}/{len(test_data)}] {sample_id} (CWE={cwe_id}, label={label})")

        # Condition A: No-RAG
        print("  → No-RAG...", end=" ", flush=True)
        messages_no_rag = build_no_rag_messages(code)
        response_no_rag = call_llm(args.model, messages_no_rag)
        pred_no_rag = parse_label(response_no_rag)
        conf_no_rag = extract_confidence(response_no_rag)
        print(f"pred={pred_no_rag}, conf={conf_no_rag:.2f}")

        no_rag_samples.append({
            "id": sample_id,
            "cwe_id": cwe_id,
            "language": language,
            "true_label": label,
            "pred": pred_no_rag,
            "confidence": conf_no_rag,
            "raw_response": response_no_rag
        })

        time.sleep(args.request_interval)

        # Condition B: RAG
        print("  → RAG...", end=" ", flush=True)
        import asyncio
        retrieved_docs = asyncio.run(rag_retriever.retrieve(code, k=5))
        messages_rag = build_rag_messages(code, retrieved_docs)
        response_rag = call_llm(args.model, messages_rag)
        pred_rag = parse_label(response_rag)
        conf_rag = extract_confidence(response_rag)
        print(f"pred={pred_rag}, conf={conf_rag:.2f}, retrieved={len(retrieved_docs)}")

        rag_samples.append({
            "id": sample_id,
            "cwe_id": cwe_id,
            "language": language,
            "true_label": label,
            "pred": pred_rag,
            "confidence": conf_rag,
            "retrieved_count": len(retrieved_docs),
            "raw_response": response_rag
        })

        if idx < len(test_data):
            time.sleep(args.request_interval)

    # 计算指标
    print()
    print("=" * 72)
    print("计算指标...")
    print("=" * 72)

    no_rag_labels = [s["true_label"] for s in no_rag_samples]
    no_rag_preds = [s["pred"] for s in no_rag_samples]
    no_rag_metrics = compute_metrics(no_rag_labels, no_rag_preds)
    no_rag_metrics["avg_confidence"] = sum(s["confidence"] for s in no_rag_samples) / len(no_rag_samples)

    rag_labels = [s["true_label"] for s in rag_samples]
    rag_preds = [s["pred"] for s in rag_samples]
    rag_metrics = compute_metrics(rag_labels, rag_preds)
    rag_metrics["avg_confidence"] = sum(s["confidence"] for s in rag_samples) / len(rag_samples)

    per_cwe_no_rag = compute_per_cwe_metrics(no_rag_samples)
    per_cwe_rag = compute_per_cwe_metrics(rag_samples)

    # 合并per-CWE结果
    per_cwe_combined = {}
    all_cwes = set(per_cwe_no_rag.keys()) | set(per_cwe_rag.keys())
    for cwe in all_cwes:
        per_cwe_combined[cwe] = {
            "no_rag": per_cwe_no_rag.get(cwe, {}),
            "rag": per_cwe_rag.get(cwe, {}),
            "sample_count": per_cwe_no_rag.get(cwe, {}).get("sample_count", 0)
        }

    # 保存结果
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = ROOT / args.output_dir / f"ablation_clean_{timestamp}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output = {
        "config": {
            "test_dataset": str(test_path),
            "rag_corpus": str(rag_path),
            "model": args.model,
            "test_size": len(test_data),
            "rag_corpus_size": len(rag_data),
            "overlap_rate": f"{overlap_rate:.1%}",
            "timestamp": timestamp
        },
        "no_rag": no_rag_metrics,
        "rag": rag_metrics,
        "per_cwe": per_cwe_combined,
        "samples": {
            "no_rag": no_rag_samples,
            "rag": rag_samples
        }
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    # 打印结果
    print()
    print("No-RAG 结果:")
    print(f"  Precision: {no_rag_metrics['precision']:.4f}")
    print(f"  Recall:    {no_rag_metrics['recall']:.4f}")
    print(f"  F1:        {no_rag_metrics['f1']:.4f}")
    print(f"  Accuracy:  {no_rag_metrics['accuracy']:.4f}")
    print()
    print("RAG 结果:")
    print(f"  Precision: {rag_metrics['precision']:.4f}")
    print(f"  Recall:    {rag_metrics['recall']:.4f}")
    print(f"  F1:        {rag_metrics['f1']:.4f}")
    print(f"  Accuracy:  {rag_metrics['accuracy']:.4f}")
    print()
    print(f"F1 提升: {rag_metrics['f1'] - no_rag_metrics['f1']:.4f} ({(rag_metrics['f1'] / no_rag_metrics['f1'] - 1) * 100:.1f}%)" if no_rag_metrics['f1'] > 0 else "F1 提升: N/A")
    print()
    print("=" * 72)
    print(f"结果已保存到: {output_path}")
    print("=" * 72)


if __name__ == "__main__":
    main()

