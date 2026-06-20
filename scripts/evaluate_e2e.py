#!/usr/bin/env python3
"""端到端漏洞检测+修复流水线

流程：
1. 检测：对每条代码运行检测系统，判断是否有漏洞
2. 修复：对检测到有漏洞的代码，自动生成修复方案
3. 输出：完整报告（检测结果 + 修复结果）

用法：
    python scripts/evaluate_e2e.py                          # 默认配置
    python scripts/evaluate_e2e.py --limit 10               # 只跑10条
    python scripts/evaluate_e2e.py --no-repair              # 只检测不修复
    python scripts/evaluate_e2e.py --no-sandbox             # 修复时不用沙箱
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


def get_kl_retriever(llm):
    from rag.knowledge_retriever import KnowledgeRAGRetriever
    v2_dir = str(ROOT / "data_v2" / "chroma_kl_db")
    v1_dir = str(ROOT / "data" / "chroma_kl_db")
    use_dir = v2_dir if Path(v2_dir).exists() else v1_dir
    retriever = KnowledgeRAGRetriever(llm=llm, persist_dir=use_dir)
    if not retriever.is_ready():
        print("警告：知识库为空，RAG将不提供参考")
        return None
    print(f"使用知识库：{use_dir}（{retriever.count()}条）")
    return retriever


def _save(path: Path, results: list, summary: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"summary": summary, "results": results},
                   indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


def compute_summary(results: list) -> dict:
    total = len(results)
    if total == 0:
        return {}

    detected = sum(1 for r in results if r.get("detection", {}).get("has_vulnerability"))
    true_vuln = sum(1 for r in results if r.get("true_label") == 1)

    # 检测指标
    tp = sum(1 for r in results
             if r.get("true_label") == 1 and r.get("detection", {}).get("has_vulnerability"))
    fp = sum(1 for r in results
             if r.get("true_label") == 0 and r.get("detection", {}).get("has_vulnerability"))
    fn = sum(1 for r in results
             if r.get("true_label") == 1 and not r.get("detection", {}).get("has_vulnerability"))
    tn = sum(1 for r in results
             if r.get("true_label") == 0 and not r.get("detection", {}).get("has_vulnerability"))

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    # 修复指标（只统计被检测到的漏洞）
    repair_results = [r for r in results if r.get("repair")]
    repair_total = len(repair_results)
    repair_success = sum(1 for r in repair_results
                         if r.get("repair", {}).get("status") == "verified_fixed")
    compilable = sum(1 for r in repair_results
                     if any(s.get("compiled") for s in
                            r.get("repair", {}).get("sandbox_results", [])))

    return {
        "total_samples": total,
        "true_vuln": true_vuln,
        "detection": {
            "detected": detected,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        },
        "repair": {
            "attempted": repair_total,
            "compilable": compilable,
            "verified_fixed": repair_success,
            "fix_rate": round(repair_success / repair_total, 4) if repair_total else 0,
        }
    }


async def run_e2e(
    test_path: Path,
    output_path: Path,
    limit: int = None,
    enable_repair: bool = True,
    enable_sandbox: bool = True,
    enable_debate: bool = True,
    resume: bool = True,
    confidence_threshold: float = 0.5,
):
    from pipeline.coordinator import Coordinator
    from agents.repair_agent import RepairAgent
    from scripts.evaluate import CONFIG_PRESETS

    llm = get_llm()
    kl_retriever = get_kl_retriever(llm)

    # 初始化检测系统
    detection_cfg = {
        "enable_router": False, "enable_hybrid": False, "enable_hyde": False,
        "enable_reranker": True, "enable_crag": False, "enable_verifier": False,
        "enable_voting": False, "enable_debate": False, "enable_kl_rag": True,
        "enable_reflection": False, "enable_plan_and_solve": False, "enable_ast_tool": False,
    }
    coordinator = Coordinator(
        llm=llm,
        chroma_persist_dir=str(ROOT / "data" / "chroma_db"),
        kl_chroma_persist_dir=str(ROOT / "data_v2" / "chroma_kl_db"),
        rag_corpus_path=str(ROOT / "data_v2" / "processed" / "rag_corpus_v2.jsonl"),
        retrieval_k=5,
        use_local_reranker=False,
        **detection_cfg,
    )

    # 初始化修复系统
    repair_agent = RepairAgent(llm=llm, kl_retriever=kl_retriever) if enable_repair else None

    # 加载测试集
    samples = []
    with open(test_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    print(f"测试集：{len(samples)} 条")

    # 断点续跑
    all_results = []
    done_ids = set()
    if resume and output_path.exists():
        existing = json.loads(output_path.read_text(encoding="utf-8"))
        all_results = existing.get("results", [])
        done_ids = {r["sample_id"] for r in all_results}
        print(f"断点续跑：已完成 {len(done_ids)} 条")

    todo = [s for s in samples if s.get("id") not in done_ids]
    if limit:
        todo = todo[:max(0, limit - len(done_ids))]
    print(f"本次运行：{len(todo)} 条\n")

    start = time.time()

    for i, sample in enumerate(todo):
        sample_id = sample.get("id", f"unknown_{i}")
        code = sample.get("vulnerable_code", "")
        true_label = sample.get("label", 0)
        cwe = sample.get("cwe_id", "UNKNOWN")
        language = sample.get("language", "C++")

        print(f"[{i+1}/{len(todo)}] {sample_id} (真实标签={'漏洞' if true_label==1 else '干净'})")

        result = {
            "sample_id": sample_id,
            "true_label": true_label,
            "true_cwe": cwe,
            "language": language,
            "detection": None,
            "repair": None,
        }

        # ── Step 1：检测 ──────────────────────────────────────────────
        try:
            t0 = time.time()
            det_output = await coordinator.run(code, language=language)
            det_elapsed = round(time.time() - t0, 2)

            verdict = det_output["verdict"]
            has_vuln = bool(verdict.get("has_vulnerability"))
            confidence = verdict.get("confidence", 0)
            final_pred = has_vuln and confidence >= confidence_threshold

            result["detection"] = {
                "has_vulnerability": final_pred,
                "raw_has_vulnerability": has_vuln,
                "vulnerability_type": verdict.get("vulnerability_type"),
                "confidence": confidence,
                "reason": verdict.get("reason", ""),
                "vulnerable_lines": det_output.get("detection", {}).get("vulnerable_lines", []),
                "elapsed": det_elapsed,
            }

            status = "✅ 检测到漏洞" if final_pred else "✅ 判断为干净"
            print(f"  检测：{status}（置信度={confidence:.2f}，耗时={det_elapsed}s）")

        except Exception as e:
            result["detection"] = {"error": str(e)[:200], "has_vulnerability": False}
            print(f"  检测：❌ 失败 - {e}")

        # ── Step 2：修复（只对检测到漏洞的代码修复）────────────────────
        if (enable_repair and repair_agent and
                result["detection"] and result["detection"].get("has_vulnerability")):

            detected_cwe = (result["detection"].get("vulnerability_type") or cwe or "UNKNOWN")
            # 提取CWE编号（如 "CWE-476: xxx" -> "CWE-476"）
            if ":" in detected_cwe:
                detected_cwe = detected_cwe.split(":")[0].strip()

            # 把检测结果传给修复系统（实现真正的串联）
            vuln_report = result["detection"].get("reason", f"{detected_cwe} 漏洞已检测到")
            vuln_lines = str(result["detection"].get("vulnerable_lines", ""))

            try:
                t0 = time.time()
                rep_output = await repair_agent.repair(
                    code=code,
                    cwe=detected_cwe,
                    language=language,
                    vulnerability_report=vuln_report,    # ← 真实检测报告
                    vulnerable_lines=vuln_lines,          # ← 真实漏洞行号
                    enable_sandbox=enable_sandbox,
                    enable_self_check=True,
                    enable_debate=enable_debate,
                )
                rep_elapsed = round(time.time() - t0, 2)

                result["repair"] = {
                    "status": rep_output.get("status"),
                    "fix_strategy": rep_output.get("fix_strategy", ""),
                    "rounds_used": rep_output.get("rounds_used", 1),
                    "confidence": rep_output.get("confidence", 0),
                    "debate_verdict": rep_output.get("debate", {}).get("verdict"),
                    "self_check_passed": rep_output.get("self_check", {}).get("all_passed"),
                    "sandbox_results": rep_output.get("sandbox_results", []),
                    "elapsed": rep_elapsed,
                    "fixed_code": rep_output.get("fixed_code", "")[:500],
                }

                status = rep_output.get("status", "unknown")
                print(f"  修复：{status}（{rep_output.get('rounds_used',1)}轮，耗时={rep_elapsed}s）")

            except Exception as e:
                result["repair"] = {"error": str(e)[:200], "status": "error"}
                print(f"  修复：❌ 失败 - {e}")

        elif enable_repair and result["detection"] and not result["detection"].get("has_vulnerability"):
            print(f"  修复：跳过（未检测到漏洞）")

        all_results.append(result)

        # 每5条保存一次
        if (i + 1) % 5 == 0 or i == len(todo) - 1:
            summary = compute_summary(all_results)
            _save(output_path, all_results, summary)
            elapsed = time.time() - start
            avg = elapsed / (i + 1)
            eta = avg * (len(todo) - i - 1)
            det = summary.get("detection", {})
            rep = summary.get("repair", {})
            print(f"\n  进度 [{i+1}/{len(todo)}] "
                  f"检测F1={det.get('f1', 0):.3f} "
                  f"修复成功率={rep.get('fix_rate', 0):.3f} "
                  f"ETA={eta/60:.1f}min\n")

    summary = compute_summary(all_results)
    _save(output_path, all_results, summary)

    print(f"\n{'='*60}")
    print(f"端到端评估完成")
    print(f"{'='*60}")
    det = summary.get("detection", {})
    rep = summary.get("repair", {})
    print(f"检测结果：P={det.get('precision',0):.4f} "
          f"R={det.get('recall',0):.4f} "
          f"F1={det.get('f1',0):.4f}")
    print(f"  TP={det.get('tp',0)} FP={det.get('fp',0)} "
          f"TN={det.get('tn',0)} FN={det.get('fn',0)}")
    print(f"修复结果：尝试={rep.get('attempted',0)} "
          f"可编译={rep.get('compilable',0)} "
          f"验证修复={rep.get('verified_fixed',0)} "
          f"修复率={rep.get('fix_rate',0):.4f}")


def main():
    parser = argparse.ArgumentParser(description="端到端漏洞检测+修复")
    parser.add_argument("--test", default="data_v2/processed/test_v2.jsonl",
                        help="测试集路径")
    parser.add_argument("--output", default=None,
                        help="输出结果路径")
    parser.add_argument("--limit", type=int, default=None,
                        help="最多运行几条")
    parser.add_argument("--no-repair", action="store_true",
                        help="只检测不修复")
    parser.add_argument("--no-sandbox", action="store_true",
                        help="修复时不用沙箱")
    parser.add_argument("--no-debate", action="store_true",
                        help="修复时不用Debate")
    parser.add_argument("--no-resume", action="store_true",
                        help="不断点续跑，从头开始")
    parser.add_argument("--threshold", type=float, default=0.5,
                        help="检测置信度阈值（默认0.5）")
    args = parser.parse_args()

    test_path = ROOT / args.test
    if not test_path.exists():
        print(f"ERROR: 测试集不存在：{test_path}")
        return

    output_path = Path(args.output) if args.output else (
        ROOT / "experiments" / "e2e" / "eval_e2e_latest.json"
    )

    print(f"端到端漏洞检测+修复系统")
    print(f"测试集：{test_path}")
    print(f"输出：{output_path}")
    print(f"修复：{'关闭' if args.no_repair else '开启'}")
    print(f"沙箱：{'关闭' if args.no_sandbox else '开启'}")

    asyncio.run(run_e2e(
        test_path=test_path,
        output_path=output_path,
        limit=args.limit,
        enable_repair=not args.no_repair,
        enable_sandbox=not args.no_sandbox,
        enable_debate=not args.no_debate,
        resume=not args.no_resume,
        confidence_threshold=args.threshold,
    ))


if __name__ == "__main__":
    main()
