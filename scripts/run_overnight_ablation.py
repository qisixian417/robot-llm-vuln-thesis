# [全量消融] 8个配置在完整161条测试集上运行（包含KL-RAG/Plan-and-Solve/AST/Verifier等），适合挂夜跑
#!/usr/bin/env python3
"""Overnight comprehensive ablation: all modules on full 161 test samples.

Configs (ordered by estimated runtime, short ones first):
  1.  naive           - pure LLM, no RAG (baseline lower bound)
  2.  rag_basic       - code-level dense RAG
  3.  6_full_crag     - best code-level RAG (all 6 components)
  4.  kl_rag_only     - KL-RAG only, no other agents
  5.  kl_rag_ast      - KL-RAG + Router + Reranker + AST Tool
  6.  kl_rag_plan     - KL-RAG + Router + Reranker + Plan-and-Solve
  7.  kl_rag_verifier - KL-RAG + Router + Reranker + Verifier (Docker)
  8.  kl_rag_ast_vote - KL-RAG + Router + Reranker + AST + Voting

(kl_rag_full is already done, skipped to save time)

Estimated total: 7-9 hours (safe for overnight)

Usage:
    python scripts/run_overnight_ablation.py           # run all
    python scripts/run_overnight_ablation.py --skip-verifier  # skip Docker
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

from scripts.evaluate import (
    CONFIG_PRESETS,
    compute_metrics,
    cwe_breakdown,
    load_jsonl,
    run_evaluation,
)

# ──────────────────────────────────────────────────────────
# Overnight configs (add to CONFIG_PRESETS so run_evaluation finds them)
# ──────────────────────────────────────────────────────────
OVERNIGHT_CONFIGS = {
    "ON_01_naive": {
        "enable_router": False, "enable_hybrid": False, "enable_hyde": False,
        "enable_reranker": False, "enable_crag": False, "enable_verifier": False,
        "enable_voting": False, "enable_debate": False, "enable_kl_rag": False,
        "enable_reflection": False, "enable_plan_and_solve": False, "enable_ast_tool": False,
    },
    "ON_02_rag_basic": {
        "enable_router": False, "enable_hybrid": False, "enable_hyde": False,
        "enable_reranker": False, "enable_crag": False, "enable_verifier": False,
        "enable_voting": False, "enable_debate": False, "enable_kl_rag": False,
        "enable_reflection": False, "enable_plan_and_solve": False, "enable_ast_tool": False,
    },
    "ON_03_full_crag": {
        "enable_router": False, "enable_hybrid": True, "enable_hyde": True,
        "enable_reranker": True, "enable_crag": True, "enable_verifier": False,
        "enable_voting": False, "enable_debate": False, "enable_kl_rag": False,
        "enable_reflection": False, "enable_plan_and_solve": False, "enable_ast_tool": False,
    },
    "ON_04_kl_rag_only": {
        "enable_router": False, "enable_hybrid": False, "enable_hyde": False,
        "enable_reranker": False, "enable_crag": False, "enable_verifier": False,
        "enable_voting": False, "enable_debate": False, "enable_kl_rag": True,
        "enable_reflection": False, "enable_plan_and_solve": False, "enable_ast_tool": False,
    },
    "ON_05_kl_rag_ast": {
        "enable_router": True, "enable_hybrid": False, "enable_hyde": False,
        "enable_reranker": True, "enable_crag": False, "enable_verifier": False,
        "enable_voting": False, "enable_debate": False, "enable_kl_rag": True,
        "enable_reflection": False, "enable_plan_and_solve": False, "enable_ast_tool": True,
    },
    "ON_06_kl_rag_plan": {
        "enable_router": True, "enable_hybrid": False, "enable_hyde": False,
        "enable_reranker": True, "enable_crag": False, "enable_verifier": False,
        "enable_voting": False, "enable_debate": False, "enable_kl_rag": True,
        "enable_reflection": False, "enable_plan_and_solve": True, "enable_ast_tool": False,
    },
    "ON_07_kl_rag_verifier": {
        "enable_router": True, "enable_hybrid": False, "enable_hyde": False,
        "enable_reranker": True, "enable_crag": False, "enable_verifier": True,
        "enable_voting": False, "enable_debate": False, "enable_kl_rag": True,
        "enable_reflection": False, "enable_plan_and_solve": False, "enable_ast_tool": False,
    },
    "ON_08_kl_rag_ast_vote": {
        "enable_router": True, "enable_hybrid": False, "enable_hyde": False,
        "enable_reranker": True, "enable_crag": False, "enable_verifier": False,
        "enable_voting": True, "enable_debate": False, "enable_kl_rag": True,
        "enable_reflection": False, "enable_plan_and_solve": False, "enable_ast_tool": True,
    },
}

# Estimated seconds per sample for ETA display
ETA_ESTIMATES = {
    "ON_01_naive": 8,
    "ON_02_rag_basic": 10,
    "ON_03_full_crag": 14,
    "ON_04_kl_rag_only": 16,
    "ON_05_kl_rag_ast": 20,
    "ON_06_kl_rag_plan": 45,
    "ON_07_kl_rag_verifier": 50,
    "ON_08_kl_rag_ast_vote": 30,
}


def print_summary_table(results: dict):
    print("\n" + "=" * 85)
    print("OVERNIGHT ABLATION RESULTS SUMMARY")
    print("=" * 85)
    print(f"{'Config':<30} {'P':>8} {'R':>8} {'F1':>8} {'Acc':>8} {'TP':>4} {'FP':>4}")
    print("-" * 85)

    # Include kl_rag_full from previous run if available
    kl_full_path = ROOT / "experiments" / "eval_kl_rag_full_test_v2_filtered.json"
    if kl_full_path.exists():
        try:
            d = json.loads(kl_full_path.read_text(encoding="utf-8"))
            m = d.get("metrics", {})
            if m:
                print(f"{'kl_rag_full (prev)':<30} "
                      f"{m['precision']:>8.4f} {m['recall']:>8.4f} "
                      f"{m['f1']:>8.4f} {m['accuracy']:>8.4f} "
                      f"{m['tp']:>4} {m['fp']:>4}  <- reference")
        except Exception:
            pass

    for name, m in sorted(results.items()):
        print(f"{name:<30} "
              f"{m['precision']:>8.4f} {m['recall']:>8.4f} "
              f"{m['f1']:>8.4f} {m['accuracy']:>8.4f} "
              f"{m['tp']:>4} {m['fp']:>4}")

    print("=" * 85)

    if results:
        best = max(results.items(), key=lambda x: x[1]["f1"])
        print(f"\nBEST F1:  {best[0]} → {best[1]['f1']:.4f}")
        best_p = max(results.items(), key=lambda x: x[1]["precision"])
        print(f"BEST P:   {best_p[0]} → {best_p[1]['precision']:.4f}")
        best_r = max(results.items(), key=lambda x: x[1]["recall"])
        print(f"BEST R:   {best_r[0]} → {best_r[1]['recall']:.4f}")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", type=str, default="data/test_v2_filtered.jsonl")
    parser.add_argument("--skip-verifier", action="store_true",
                        help="Skip Docker-based verifier (ON_07)")
    parser.add_argument("--only", type=str, default=None,
                        help="Comma-separated config keys to run (e.g. ON_01_naive,ON_04_kl_rag_only)")
    args = parser.parse_args()

    test_path = ROOT / args.test
    if not test_path.exists():
        print(f"ERROR: {test_path} not found")
        return

    samples = load_jsonl(test_path)
    print(f"Loaded {len(samples)} samples from {test_path.name}")

    configs_to_run = list(OVERNIGHT_CONFIGS.keys())
    if args.only:
        configs_to_run = [c for c in configs_to_run if c in args.only.split(",")]
    if args.skip_verifier:
        configs_to_run = [c for c in configs_to_run if "verifier" not in c]

    total_est = sum(
        ETA_ESTIMATES.get(c, 20) * len(samples) / 60
        for c in configs_to_run
    )
    print(f"\nConfigs to run: {len(configs_to_run)}")
    print(f"Estimated total time: {total_est:.0f} min ({total_est/60:.1f} hours)")
    print(f"Configs: {', '.join(configs_to_run)}\n")

    out_dir = ROOT / "experiments" / "overnight"
    out_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    total_start = time.time()

    for name in configs_to_run:
        cfg = OVERNIGHT_CONFIGS[name]
        CONFIG_PRESETS[name] = cfg
        output_path = out_dir / f"{name}.json"

        eta_s = ETA_ESTIMATES.get(name, 20) * len(samples)
        print(f"\n{'#' * 65}")
        print(f"# {name}  (~{eta_s//60}min)")
        print(f"{'#' * 65}")

        try:
            metrics = await run_evaluation(
                test_samples=samples,
                config_name=name,
                output_path=output_path,
                limit=None,
                resume=True,
            )
            results[name] = metrics
        except Exception as e:
            print(f"  ERROR in {name}: {e}")
            import traceback
            traceback.print_exc()
            results[name] = {"precision": 0, "recall": 0, "f1": 0, "accuracy": 0,
                             "tp": 0, "fp": 0, "tn": 0, "fn": 0, "total": 0, "error": str(e)}

    total_elapsed = (time.time() - total_start) / 60
    print(f"\nTotal elapsed: {total_elapsed:.1f} min")

    print_summary_table(results)

    summary_path = out_dir / "overnight_summary.json"
    summary_path.write_text(
        json.dumps({"results": results}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"\nSummary saved: {summary_path}")


if __name__ == "__main__":
    asyncio.run(main())
