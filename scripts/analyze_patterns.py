"""漏洞Pattern分析：按CWE类型总结ROS代码中的漏洞模式

运行方式：
    python3 scripts/analyze_patterns.py
    python3 scripts/analyze_patterns.py --no-llm  # 只输出统计，不调用LLM
"""

import argparse
import json
import os
import random
import sys
import time
from collections import defaultdict
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

MAX_SAMPLES_PER_CWE = 15  # 每个CWE类型最多分析的样本数


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    items = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items


def call_llm(messages: List[Dict[str, str]], retries: int = 3) -> str:
    payload = json.dumps({
        "model": "qwen-plus",
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": 4096
    }).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}"
    }
    for attempt in range(retries):
        try:
            req = urllib.request.Request(API_URL, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=120, context=ssl_ctx) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            print(f"    API调用失败(第{attempt+1}次): {e}")
            if attempt < retries - 1:
                time.sleep(5)
    return ""


def compute_statistics(train_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """计算数据集统计信息"""
    vuln_samples = [s for s in train_data if int(s.get("label", 0)) == 1]

    cwe_groups = defaultdict(list)
    for s in vuln_samples:
        cwe_id = s.get("cwe_id") or "unknown"
        cwe_groups[cwe_id].append(s)

    stats = {}
    total_vuln = len(vuln_samples)

    for cwe_id, samples in sorted(cwe_groups.items(), key=lambda x: -len(x[1])):
        lang_count = defaultdict(int)
        repo_count = defaultdict(int)
        severity_count = defaultdict(int)

        for s in samples:
            lang_count[s.get("language", "unknown")] += 1
            repo_count[s.get("repo", "unknown")] += 1
            severity_count[s.get("severity", "unknown")] += 1

        top_repos = sorted(repo_count.items(), key=lambda x: -x[1])[:5]

        stats[cwe_id] = {
            "cwe_name": samples[0].get("cwe_name", ""),
            "sample_count": len(samples),
            "percentage": round(len(samples) / total_vuln * 100, 1) if total_vuln else 0,
            "language_breakdown": dict(lang_count),
            "top_repos": [{"repo": r, "count": c} for r, c in top_repos],
            "severity_breakdown": dict(severity_count),
        }

    return {
        "total_vulnerable": total_vuln,
        "total_samples": len(train_data),
        "cwe_types": len(cwe_groups),
        "per_cwe": stats
    }


def analyze_cwe_patterns(cwe_id: str, cwe_name: str, samples: List[Dict[str, Any]]) -> str:
    """使用LLM分析某个CWE类型的漏洞模式"""
    # 如果样本太多，随机采样
    if len(samples) > MAX_SAMPLES_PER_CWE:
        selected = random.sample(samples, MAX_SAMPLES_PER_CWE)
    else:
        selected = samples

    # 构建代码片段
    code_parts = []
    for i, s in enumerate(selected, 1):
        code = s.get("vulnerable_code", "")
        repo = s.get("repo", "unknown")
        desc = s.get("description", "")
        code_parts.append(
            f"--- 样本{i} (来源: {repo}) ---\n"
            f"描述: {desc}\n"
            f"代码:\n{code[:1500]}\n"
        )

    code_text = "\n".join(code_parts)

    prompt = f"""你是一名机器人软件安全专家。以下是 {len(selected)} 个来自ROS（机器人操作系统）项目的代码样本，
它们都包含 {cwe_id}: {cwe_name} 类型的安全漏洞。

{code_text}

请分析这些样本，总结以下内容（用中文回答，返回JSON格式）：

{{
  "common_patterns": ["模式1描述", "模式2描述", ...],
  "ros_characteristics": ["ROS特征1", "ROS特征2", ...],
  "static_tool_limitations": ["静态工具局限1", "静态工具局限2", ...],
  "general_vs_ros_diff": "这类漏洞在ROS代码中与通用代码的主要区别",
  "detection_suggestions": ["检测建议1", "检测建议2", ...]
}}

要求：
1. common_patterns: 总结这些代码中导致{cwe_name}的共同代码模式（至少3个）
2. ros_characteristics: 这些漏洞与ROS框架的哪些特性相关（如callback、publisher/subscriber、lifecycle、多线程等）
3. static_tool_limitations: 为什么Cppcheck/Semgrep等传统静态分析工具无法检测这些漏洞
4. general_vs_ros_diff: 同样的{cwe_name}在ROS代码中有什么不同于通用软件的特点
5. detection_suggestions: 针对ROS代码中这类漏洞的检测建议

只返回JSON，不要其他文字。"""

    messages = [
        {"role": "system", "content": "你是机器人软件安全专家，擅长分析ROS代码中的安全漏洞模式。"},
        {"role": "user", "content": prompt}
    ]

    return call_llm(messages)


def generate_markdown_report(stats: Dict[str, Any], pattern_results: Dict[str, Any]) -> str:
    """生成Markdown格式的分析报告"""
    lines = [
        "# ROS代码漏洞Pattern分析报告",
        "",
        "## 1. 数据集概览",
        "",
        f"- 总样本数: {stats['total_samples']}",
        f"- 漏洞样本数: {stats['total_vulnerable']}",
        f"- CWE类型数: {stats['cwe_types']}",
        "",
        "### CWE类型分布",
        "",
        "| CWE | 名称 | 样本数 | 占比 | 主要语言 |",
        "|-----|------|--------|------|----------|",
    ]

    for cwe_id, info in sorted(stats["per_cwe"].items(), key=lambda x: -x[1]["sample_count"]):
        lang = ", ".join(f"{k}({v})" for k, v in info["language_breakdown"].items())
        lines.append(f"| {cwe_id} | {info['cwe_name']} | {info['sample_count']} | {info['percentage']}% | {lang} |")

    lines.extend(["", "## 2. 各CWE类型漏洞Pattern分析", ""])

    for cwe_id in sorted(pattern_results.keys()):
        result = pattern_results[cwe_id]
        cwe_name = stats["per_cwe"].get(cwe_id, {}).get("cwe_name", "")
        sample_count = stats["per_cwe"].get(cwe_id, {}).get("sample_count", 0)

        lines.extend([
            f"### {cwe_id}: {cwe_name} ({sample_count}个样本)",
            "",
        ])

        if isinstance(result, dict):
            # Common patterns
            patterns = result.get("common_patterns", [])
            if patterns:
                lines.append("**常见代码模式:**")
                for p in patterns:
                    lines.append(f"- {p}")
                lines.append("")

            # ROS characteristics
            ros_chars = result.get("ros_characteristics", [])
            if ros_chars:
                lines.append("**ROS特征:**")
                for r in ros_chars:
                    lines.append(f"- {r}")
                lines.append("")

            # Static tool limitations
            limitations = result.get("static_tool_limitations", [])
            if limitations:
                lines.append("**静态工具局限:**")
                for l in limitations:
                    lines.append(f"- {l}")
                lines.append("")

            # General vs ROS diff
            diff = result.get("general_vs_ros_diff", "")
            if diff:
                lines.append(f"**与通用代码的区别:** {diff}")
                lines.append("")

            # Detection suggestions
            suggestions = result.get("detection_suggestions", [])
            if suggestions:
                lines.append("**检测建议:**")
                for s in suggestions:
                    lines.append(f"- {s}")
                lines.append("")
        else:
            lines.append(f"分析结果: {result}")
            lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="ROS漏洞Pattern分析")
    parser.add_argument("--train-data", type=str, default="data/train_cleaned.jsonl")
    parser.add_argument("--rag-corpus", type=str, default="data/rag_corpus_cleaned.jsonl")
    parser.add_argument("--output-dir", type=str, default="experiments")
    parser.add_argument("--no-llm", action="store_true", help="只输出统计，不调用LLM分析")
    args = parser.parse_args()

    train_path = ROOT / args.train_data
    rag_path = ROOT / args.rag_corpus

    print("=" * 72)
    print("ROS代码漏洞Pattern分析")
    print("=" * 72)

    # 加载数据
    train_data = load_jsonl(train_path)
    rag_data = load_jsonl(rag_path)
    print(f"训练集: {len(train_data)} 样本")
    print(f"RAG语料库: {len(rag_data)} 样本")

    # 计算统计信息
    stats = compute_statistics(train_data)
    print(f"\n漏洞样本: {stats['total_vulnerable']} 个")
    print(f"CWE类型: {stats['cwe_types']} 种")
    print()

    for cwe_id, info in sorted(stats["per_cwe"].items(), key=lambda x: -x[1]["sample_count"]):
        print(f"  {cwe_id} ({info['cwe_name']}): {info['sample_count']} 样本 ({info['percentage']}%)")

    # LLM分析
    pattern_results = {}

    if not args.no_llm:
        if not API_KEY:
            print("\n⚠️  DASHSCOPE_API_KEY 未配置，跳过LLM分析")
            args.no_llm = True

    if not args.no_llm:
        print("\n开始LLM分析...")
        vuln_samples = [s for s in train_data if int(s.get("label", 0)) == 1 and s.get("cwe_id")]
        cwe_groups = defaultdict(list)
        for s in vuln_samples:
            cwe_groups[s.get("cwe_id")].append(s)

        for cwe_id in sorted(cwe_groups.keys()):
            samples = cwe_groups[cwe_id]
            cwe_name = samples[0].get("cwe_name", "")
            print(f"\n分析 {cwe_id}: {cwe_name} ({len(samples)} 样本)...")

            response = analyze_cwe_patterns(cwe_id, cwe_name, samples)

            try:
                # 尝试提取JSON
                import re
                json_match = re.search(r'\{[\s\S]*\}', response)
                if json_match:
                    pattern_results[cwe_id] = json.loads(json_match.group())
                    print(f"  ✅ 分析完成")
                else:
                    pattern_results[cwe_id] = {"raw_response": response}
                    print(f"  ⚠️ 无法解析JSON，保存原始响应")
            except json.JSONDecodeError:
                pattern_results[cwe_id] = {"raw_response": response}
                print(f"  ⚠️ JSON解析失败，保存原始响应")

            time.sleep(2)

    # 保存结果
    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    # JSON输出
    json_output = {
        "statistics": stats,
        "pattern_analysis": pattern_results
    }
    json_path = output_dir / "pattern_analysis.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_output, f, ensure_ascii=False, indent=2)
    print(f"\n✅ JSON结果已保存到: {json_path}")

    # Markdown输出
    md_content = generate_markdown_report(stats, pattern_results)
    md_path = output_dir / "pattern_analysis.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    print(f"✅ Markdown报告已保存到: {md_path}")

    print("\n" + "=" * 72)
    print("分析完成！")
    print("=" * 72)


if __name__ == "__main__":
    main()
