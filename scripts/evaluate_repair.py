#!/usr/bin/env python3
"""修复系统评估脚本：对测试集漏洞样本运行修复，计算可编译率/漏洞消除率/CodeBLEU。

Usage:
    python scripts/evaluate_repair.py                    # 默认配置
    python scripts/evaluate_repair.py --limit 20         # 只跑前20条
    python scripts/evaluate_repair.py --no-sandbox       # 不用沙箱（快速模式）
    python scripts/evaluate_repair.py --no-debate        # 不用Debate
"""

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")


def get_llm():
    from langchain_openai import ChatOpenAI
    return ChatOpenAI(
        model=os.getenv("MODEL_NAME", "qwen-plus"),
        openai_api_key=os.getenv("DASHSCOPE_API_KEY"),
        openai_api_base=os.getenv("LLM_BASE_URL",
                                  "https://dashscope.aliyuncs.com/compatible-mode/v1"),
        temperature=0.1,
    )


def get_kl_retriever(llm, persist_dir: str):
    """加载 KL-RAG 知识库，优先用 v2，回退到 v1。"""
    from rag.knowledge_retriever import KnowledgeRAGRetriever
    v2_dir = str(ROOT / "data_v2" / "chroma_kl_db")
    v1_dir = str(ROOT / "data" / "chroma_kl_db")
    use_dir = v2_dir if Path(v2_dir).exists() else v1_dir
    print(f"使用知识库: {use_dir}")
    retriever = KnowledgeRAGRetriever(llm=llm, persist_dir=use_dir)
    if not retriever.is_ready():
        print("警告: 知识库为空，RAG 将不提供修复参考")
        return None
    return retriever


def simple_code_similarity(code1: str, code2: str) -> float:
    """简单的行级代码相似度（替代 CodeBLEU，无需额外依赖）。"""
    lines1 = set(l.strip() for l in code1.splitlines() if l.strip())
    lines2 = set(l.strip() for l in code2.splitlines() if l.strip())
    if not lines1 and not lines2:
        return 1.0
    if not lines1 or not lines2:
        return 0.0
    intersection = lines1 & lines2
    return len(intersection) / max(len(lines1), len(lines2))


def compute_repair_metrics(results: list) -> dict:
    """计算修复评估指标。"""
    total = len(results)
    if total == 0:
        return {}

    compiled = sum(1 for r in results if r.get("compiled", False))
    vuln_eliminated = sum(1 for r in results if r.get("vuln_eliminated", False))
    debate_approved = sum(1 for r in results if r.get("debate_verdict") == "approved")
    self_check_passed = sum(1 for r in results if r.get("self_check_passed", False))
    new_vuln = sum(1 for r in results if r.get("introduced_new_vuln", False))
    similarities = [r["similarity"] for r in results if r.get("similarity") is not None]

    return {
        "total": total,
        "compilable_rate": round(compiled / total, 4),
        "vuln_elimination_rate": round(vuln_eliminated / total, 4),
        "debate_approval_rate": round(debate_approved / total, 4),
        "self_check_pass_rate": round(self_check_passed / total, 4),
        "new_vuln_rate": round(new_vuln / total, 4),
        "avg_similarity": round(sum(similarities) / len(similarities), 4) if similarities else 0,
        "compiled": compiled,
        "vuln_eliminated": vuln_eliminated,
    }


def cwe_breakdown(results: list) -> dict:
    """按 CWE 统计修复成功率。"""
    by_cwe = {}
    for r in results:
        cwe = r.get("cwe", "unknown")
        if cwe not in by_cwe:
            by_cwe[cwe] = {"total": 0, "eliminated": 0}
        by_cwe[cwe]["total"] += 1
        if r.get("vuln_eliminated"):
            by_cwe[cwe]["eliminated"] += 1
    for cwe, d in by_cwe.items():
        d["rate"] = round(d["eliminated"] / d["total"], 4) if d["total"] else 0
    return by_cwe


async def run_repair_evaluation(
    test_path: Path,
    output_path: Path,
    limit: int = None,
    enable_sandbox: bool = True,
    enable_self_check: bool = True,
    enable_debate: bool = True,
    resume: bool = True,
):
    from agents.repair_agent import RepairAgent

    llm = get_llm()
    kl_retriever = get_kl_retriever(llm, "")
    agent = RepairAgent(llm=llm, kl_retriever=kl_retriever)

    # 加载测试集（只取漏洞样本）
    all_samples = []
    with open(test_path, encoding="utf-8") as f:
        for line in f:
            s = json.loads(line.strip())
            if s.get("label") == 1:
                all_samples.append(s)

    print(f"测试集漏洞样本: {len(all_samples)} 条")

    # 断点续跑
    done_ids = set()
    all_results = []
    if resume and output_path.exists():
        existing = json.loads(output_path.read_text(encoding="utf-8"))
        all_results = existing.get("results", [])
        done_ids = {r["sample_id"] for r in all_results}
        print(f"断点续跑: 已完成 {len(done_ids)} 条")

    samples = [s for s in all_samples if s.get("id") not in done_ids]
    if limit:
        samples = samples[:max(0, limit - len(done_ids))]

    print(f"本次运行: {len(samples)} 条")
    start = time.time()

    for i, sample in enumerate(samples):
        sample_id = sample.get("id", f"unknown_{i}")
        code = sample.get("vulnerable_code", "")
        cwe = sample.get("cwe_id", "UNKNOWN")
        language = sample.get("language", "C++")
        fixed_code_gt = sample.get("fixed_code", "")  # ground truth（成对数据）

        print(f"\n[{i+1}/{len(samples)}] {sample_id} ({cwe})")

        try:
            t0 = time.time()
            repair_output = await agent.repair(
                code=code,
                cwe=cwe,
                language=language,
                vulnerability_report=f"CWE {cwe} vulnerability detected",
                vulnerable_lines="",
                enable_sandbox=enable_sandbox,
                enable_self_check=enable_self_check,
                enable_debate=enable_debate,
            )
            elapsed = time.time() - t0

            fixed_code = repair_output.get("fixed_code", "")
            status = repair_output.get("status", "failed")
            sandbox_results = repair_output.get("sandbox_results", [])

            compiled = any(r.get("compiled") for r in sandbox_results) if sandbox_results else (status != "failed")
            sandbox_passed = any(
                r.get("compiled") and not r.get("still_vulnerable")
                for r in sandbox_results
            ) if sandbox_results else False
            debate_approved = repair_output.get("debate", {}).get("verdict") == "approved"

            # 双重判定：沙箱通过 AND Debate approved 才算真正消除
            vuln_eliminated = sandbox_passed and debate_approved

            similarity = simple_code_similarity(fixed_code, fixed_code_gt) if fixed_code_gt else None

            result = {
                "sample_id": sample_id,
                "cwe": cwe,
                "language": language,
                "status": status,
                "compiled": compiled,
                "vuln_eliminated": vuln_eliminated,
                "introduced_new_vuln": False,
                "similarity": similarity,
                "rounds_used": repair_output.get("rounds_used", 1),
                "round_history": repair_output.get("round_history", []),
                "confidence": repair_output.get("confidence", 0),
                "fix_strategy": repair_output.get("fix_strategy", ""),
                "debate_verdict": repair_output.get("debate", {}).get("verdict"),
                "self_check_passed": repair_output.get("self_check", {}).get("all_passed", False),
                "elapsed": round(elapsed, 2),
            }
        except Exception as e:
            result = {
                "sample_id": sample_id,
                "cwe": cwe,
                "language": language,
                "status": "error",
                "compiled": False,
                "vuln_eliminated": False,
                "error": str(e)[:200],
                "elapsed": 0,
            }
            print(f"  [错误] {e}")

        all_results.append(result)

        # 每5条保存一次
        if (i + 1) % 5 == 0 or i == len(samples) - 1:
            metrics = compute_repair_metrics(all_results)
            _save(output_path, all_results, metrics)
            avg_time = (time.time() - start) / (i + 1)
            eta = avg_time * (len(samples) - i - 1)
            print(f"  进度: [{i+1}/{len(samples)}] "
                  f"编译率={metrics.get('compilable_rate', 0):.3f} "
                  f"消除率={metrics.get('vuln_elimination_rate', 0):.3f} "
                  f"ETA={eta/60:.1f}min")

    metrics = compute_repair_metrics(all_results)
    cwe_stats = cwe_breakdown(all_results)
    _save(output_path, all_results, metrics, cwe_stats)

    print(f"\n=== 修复评估结果 ===")
    print(f"  总样本: {metrics['total']}")
    print(f"  可编译率: {metrics['compilable_rate']:.4f}")
    print(f"  漏洞消除率: {metrics['vuln_elimination_rate']:.4f}")
    print(f"  Debate通过率: {metrics['debate_approval_rate']:.4f}")
    print(f"  LLM自检通过率: {metrics['self_check_pass_rate']:.4f}")
    print(f"  平均相似度: {metrics['avg_similarity']:.4f}")
    print(f"\nPer-CWE 消除率:")
    for cwe, d in sorted(cwe_stats.items()):
        print(f"  {cwe}: {d['eliminated']}/{d['total']} = {d['rate']:.2f}")


def _save(path: Path, results: list, metrics: dict, cwe_stats: dict = None):
    path.parent.mkdir(parents=True, exist_ok=True)
    out = {"results": results, "metrics": metrics}
    if cwe_stats:
        out["cwe_breakdown"] = cwe_stats
    path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", default="data_v2/processed/test_v2.jsonl")
    parser.add_argument("--output", default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--no-sandbox", action="store_true")
    parser.add_argument("--no-self-check", action="store_true")
    parser.add_argument("--no-debate", action="store_true")
    parser.add_argument("--no-resume", action="store_true")
    args = parser.parse_args()

    test_path = ROOT / args.test
    if not test_path.exists():
        print(f"ERROR: {test_path} not found")
        return

    output_path = Path(args.output) if args.output else (
        ROOT / "experiments" / "repair" / "eval_repair_v2.json"
    )

    asyncio.run(run_repair_evaluation(
        test_path=test_path,
        output_path=output_path,
        limit=args.limit,
        enable_sandbox=not args.no_sandbox,
        enable_self_check=not args.no_self_check,
        enable_debate=not args.no_debate,
        resume=not args.no_resume,
    ))


if __name__ == "__main__":
    main()
