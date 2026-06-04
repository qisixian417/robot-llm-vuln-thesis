# [消融实验] 运行预定义的多组消融配置（config 1~10），每组在同一测试集上跑，输出增量F1对比表
#!/usr/bin/env python3
"""D2: Ablation study.

Runs evaluation under multiple component configurations to measure
each component's contribution to the final F1 score.

Configurations (incremental):
  1. naive            : Pure LLM (no RAG, no Agent) - baseline
  2. +rag_basic       : Naive RAG (Dense only)
  3. +hybrid          : + BM25 hybrid retrieval
  4. +hyde            : + HyDE query rewriting
  5. +reranker        : + Cross-Encoder reranking
  6. +crag            : + CRAG quality correction
  7. +router          : + CWE Router (full RAG group)
  8. +verifier        : + Sandbox verification (optional, slow)

Usage:
    python scripts/run_ablation.py                 # Run all (~ 1-2h)
    python scripts/run_ablation.py --limit 30      # Quick check (~ 15min)
    python scripts/run_ablation.py --skip-verifier # Skip slow verifier
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Dict, List

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


# Incremental ablation configurations
ABLATION_CONFIGS = {
    "1_naive": {
        "enable_router": False, "enable_hybrid": False, "enable_hyde": False,
        "enable_reranker": False, "enable_crag": False, "enable_verifier": False,
        "enable_voting": False, "enable_debate": False,
    },
    "2_rag_basic": {
        "enable_router": False, "enable_hybrid": False, "enable_hyde": False,
        "enable_reranker": False, "enable_crag": False, "enable_verifier": False,
        "enable_voting": False, "enable_debate": False,
    },
    "3_hybrid": {
        "enable_router": False, "enable_hybrid": True, "enable_hyde": False,
        "enable_reranker": False, "enable_crag": False, "enable_verifier": False,
        "enable_voting": False, "enable_debate": False,
    },
    "4_hybrid_hyde": {
        "enable_router": False, "enable_hybrid": True, "enable_hyde": True,
        "enable_reranker": False, "enable_crag": False, "enable_verifier": False,
        "enable_voting": False, "enable_debate": False,
    },
    "5_hybrid_hyde_rerank": {
        "enable_router": False, "enable_hybrid": True, "enable_hyde": True,
        "enable_reranker": True, "enable_crag": False, "enable_verifier": False,
        "enable_voting": False, "enable_debate": False,
    },
    "6_hybrid_hyde_rerank_crag": {
        "enable_router": False, "enable_hybrid": True, "enable_hyde": True,
        "enable_reranker": True, "enable_crag": True, "enable_verifier": False,
        "enable_voting": False, "enable_debate": False,
    },
    "7_full_no_verifier": {
        "enable_router": True, "enable_hybrid": True, "enable_hyde": True,
        "enable_reranker": True, "enable_crag": True, "enable_verifier": False,
        "enable_voting": False, "enable_debate": False,
    },
    "8_full_with_voting": {
        "enable_router": True, "enable_hybrid": True, "enable_hyde": True,
        "enable_reranker": True, "enable_crag": True, "enable_verifier": False,
        "enable_voting": True, "enable_debate": False,
    },
    "9_full_with_debate": {
        "enable_router": True, "enable_hybrid": True, "enable_hyde": True,
        "enable_reranker": True, "enable_crag": True, "enable_verifier": False,
        "enable_voting": False, "enable_debate": True,
    },
    "10_full_with_verifier": {
        "enable_router": True, "enable_hybrid": True, "enable_hyde": True,
        "enable_reranker": True, "enable_crag": True, "enable_verifier": True,
        "enable_voting": False, "enable_debate": False,
    },
}


def print_ablation_table(results: Dict[str, Dict]):
    """Print results as a comparison table."""
    print("\n" + "=" * 80)
    print("ABLATION STUDY RESULTS")
    print("=" * 80)
    print(f"{'Config':<32} {'P':>8} {'R':>8} {'F1':>8} {'Acc':>8}")
    print("-" * 80)
    for name in ABLATION_CONFIGS.keys():
        if name not in results:
            continue
        m = results[name]
        print(f"{name:<32} {m['precision']:>8.4f} {m['recall']:>8.4f} {m['f1']:>8.4f} {m['accuracy']:>8.4f}")
    print("=" * 80)


def print_incremental_gains(results: Dict[str, Dict]):
    """Print F1 gains between consecutive configs."""
    print("\n" + "=" * 60)
    print("INCREMENTAL F1 GAINS")
    print("=" * 60)
    keys = list(ABLATION_CONFIGS.keys())
    prev_f1 = None
    for k in keys:
        if k not in results:
            continue
        f1 = results[k]["f1"]
        if prev_f1 is not None:
            delta = f1 - prev_f1
            sign = "+" if delta >= 0 else ""
            print(f"  {k:<32} F1={f1:.4f} ({sign}{delta:+.4f})")
        else:
            print(f"  {k:<32} F1={f1:.4f}  (baseline)")
        prev_f1 = f1


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", type=str, default="data/test_v2_filtered.jsonl")
    parser.add_argument("--limit", type=int, default=None,
                        help="Limit samples per config (default: all)")
    parser.add_argument("--skip-verifier", action="store_true",
                        help="Skip the verifier config (slow due to compilation)")
    parser.add_argument("--only", type=str, default=None,
                        help="Run only specific configs (comma-separated names)")
    args = parser.parse_args()

    test_path = ROOT / args.test
    if not test_path.exists():
        print(f"ERROR: {test_path} not found")
        return

    samples = load_jsonl(test_path)
    print(f"Loaded {len(samples)} samples from {test_path.name}")
    if args.limit:
        print(f"Limiting to first {args.limit} samples per config")

    results: Dict[str, Dict] = {}
    output_dir = ROOT / "experiments" / "ablation"
    output_dir.mkdir(parents=True, exist_ok=True)

    configs_to_run = list(ABLATION_CONFIGS.keys())
    if args.only:
        only_set = set(args.only.split(","))
        configs_to_run = [c for c in configs_to_run if c in only_set]
    if args.skip_verifier:
        configs_to_run = [c for c in configs_to_run if "verifier" not in c]

    for name in configs_to_run:
        print(f"\n{'#' * 60}")
        print(f"# Running: {name}")
        print(f"{'#' * 60}")

        # Inject the config into CONFIG_PRESETS so evaluate.run_evaluation can find it
        CONFIG_PRESETS[name] = ABLATION_CONFIGS[name]

        output_path = output_dir / f"{name}.json"
        metrics = await run_evaluation(
            test_samples=samples,
            config_name=name,
            output_path=output_path,
            limit=args.limit,
            resume=True,
        )
        results[name] = metrics

    print_ablation_table(results)
    print_incremental_gains(results)

    # Save combined summary
    summary_path = output_dir / "ablation_summary.json"
    summary_path.write_text(
        json.dumps({"results": results}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"\nSummary saved to: {summary_path}")


if __name__ == "__main__":
    asyncio.run(main())
