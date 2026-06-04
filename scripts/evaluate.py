# [实验评估] 在测试集上运行单个配置并计算P/R/F1，支持断点续跑；定义所有CONFIG_PRESETS
#!/usr/bin/env python3
"""D1: Batch evaluation script.

Runs the full pipeline on the test set and computes Precision/Recall/F1.
Supports resumable runs (saves intermediate results, can pick up where left off).

Usage:
    python scripts/evaluate.py                              # Default: filtered test set
    python scripts/evaluate.py --test data/test_v2.jsonl    # Use a specific test set
    python scripts/evaluate.py --config full                # Full pipeline (default)
    python scripts/evaluate.py --config naive               # Naive RAG baseline
    python scripts/evaluate.py --limit 20                   # Only run first 20 samples
"""

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")


def get_llm():
    from langchain_openai import ChatOpenAI
    return ChatOpenAI(
        model=os.getenv("MODEL_NAME") or os.getenv("LLM_MODEL", "qwen-plus"),
        openai_api_key=os.getenv("DASHSCOPE_API_KEY"),
        openai_api_base=os.getenv("LLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
        temperature=0.1,
    )


def load_jsonl(path: Path) -> List[dict]:
    samples = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


CONFIG_PRESETS = {
    "naive": {
        "enable_router": False,
        "enable_hybrid": False,
        "enable_hyde": False,
        "enable_reranker": False,
        "enable_crag": False,
        "enable_verifier": False,
        "enable_voting": False,
        "enable_debate": False,
    },
    "rag_only": {
        "enable_router": False,
        "enable_hybrid": True,
        "enable_hyde": True,
        "enable_reranker": True,
        "enable_crag": True,
        "enable_verifier": False,
        "enable_voting": False,
        "enable_debate": False,
    },
    "agent_only": {
        "enable_router": True,
        "enable_hybrid": False,
        "enable_hyde": False,
        "enable_reranker": False,
        "enable_crag": False,
        "enable_verifier": False,
        "enable_voting": False,
        "enable_debate": False,
    },
    "full": {
        "enable_router": True,
        "enable_hybrid": True,
        "enable_hyde": True,
        "enable_reranker": True,
        "enable_crag": True,
        "enable_verifier": False,
        "enable_voting": False,
        "enable_debate": False,
    },
    "full_with_voting": {
        "enable_router": True,
        "enable_hybrid": True,
        "enable_hyde": True,
        "enable_reranker": True,
        "enable_crag": True,
        "enable_verifier": False,
        "enable_voting": True,
        "enable_debate": False,
    },
    "full_with_debate": {
        "enable_router": True,
        "enable_hybrid": True,
        "enable_hyde": True,
        "enable_reranker": True,
        "enable_crag": True,
        "enable_verifier": False,
        "enable_voting": False,
        "enable_debate": True,
    },
    "full_with_verifier": {
        "enable_router": True,
        "enable_hybrid": True,
        "enable_hyde": True,
        "enable_reranker": True,
        "enable_crag": True,
        "enable_verifier": True,
        "enable_voting": False,
        "enable_debate": False,
    },
    "kl_rag_only": {
        "enable_router": False,
        "enable_hybrid": False,
        "enable_hyde": False,
        "enable_reranker": False,
        "enable_crag": False,
        "enable_verifier": False,
        "enable_voting": False,
        "enable_debate": False,
        "enable_kl_rag": True,
    },
    "kl_rag_full": {
        "enable_router": True,
        "enable_hybrid": False,
        "enable_hyde": False,
        "enable_reranker": True,
        "enable_crag": False,
        "enable_verifier": False,
        "enable_voting": False,
        "enable_debate": False,
        "enable_kl_rag": True,
    },
    "kl_rag_full_voting": {
        "enable_router": True,
        "enable_hybrid": False,
        "enable_hyde": False,
        "enable_reranker": True,
        "enable_crag": False,
        "enable_verifier": False,
        "enable_voting": True,
        "enable_debate": False,
        "enable_kl_rag": True,
        "enable_reflection": False,
        "enable_plan_and_solve": False,
    },
    "kl_rag_full_reflection": {
        "enable_router": True,
        "enable_hybrid": False,
        "enable_hyde": False,
        "enable_reranker": True,
        "enable_crag": False,
        "enable_verifier": False,
        "enable_voting": False,
        "enable_debate": False,
        "enable_kl_rag": True,
        "enable_reflection": True,
        "enable_plan_and_solve": False,
    },
    "kl_rag_plan_and_solve": {
        "enable_router": True,
        "enable_hybrid": False,
        "enable_hyde": False,
        "enable_reranker": True,
        "enable_crag": False,
        "enable_verifier": False,
        "enable_voting": False,
        "enable_debate": False,
        "enable_kl_rag": True,
        "enable_reflection": False,
        "enable_plan_and_solve": True,
    },
    "kl_rag_plan_and_solve": {
        "enable_router": True,
        "enable_hybrid": False,
        "enable_hyde": False,
        "enable_reranker": True,
        "enable_crag": False,
        "enable_verifier": False,
        "enable_voting": False,
        "enable_debate": False,
        "enable_kl_rag": True,
        "enable_reflection": False,
        "enable_plan_and_solve": True,
        "enable_ast_tool": False,
    },
    "kl_rag_ast": {
        "enable_router": True,
        "enable_hybrid": False,
        "enable_hyde": False,
        "enable_reranker": True,
        "enable_crag": False,
        "enable_verifier": False,
        "enable_voting": False,
        "enable_debate": False,
        "enable_kl_rag": True,
        "enable_reflection": False,
        "enable_plan_and_solve": False,
        "enable_ast_tool": True,
    },
    "kl_rag_full_verifier": {
        "enable_router": True,
        "enable_hybrid": False,
        "enable_hyde": False,
        "enable_reranker": True,
        "enable_crag": False,
        "enable_verifier": True,
        "enable_voting": False,
        "enable_debate": False,
        "enable_kl_rag": True,
        "enable_reflection": False,
        "enable_plan_and_solve": False,
        "enable_ast_tool": False,
    },
    "kl_rag_ast_voting": {
        "enable_router": True,
        "enable_hybrid": False,
        "enable_hyde": False,
        "enable_reranker": True,
        "enable_crag": False,
        "enable_verifier": False,
        "enable_voting": True,
        "enable_debate": False,
        "enable_kl_rag": True,
        "enable_reflection": False,
        "enable_plan_and_solve": False,
        "enable_ast_tool": True,
    },
}


def compute_metrics(predictions: List[dict]) -> Dict:
    """Compute P/R/F1 for vulnerability detection (binary)."""
    tp = fp = tn = fn = 0
    for p in predictions:
        pred_vuln = p.get("predicted_vuln", False)
        true_vuln = p.get("true_label") == 1
        if pred_vuln and true_vuln:
            tp += 1
        elif pred_vuln and not true_vuln:
            fp += 1
        elif not pred_vuln and not true_vuln:
            tn += 1
        elif not pred_vuln and true_vuln:
            fn += 1

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    return {
        "total": total,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def cwe_breakdown(predictions: List[dict]) -> Dict:
    """Per-CWE recall (only for vulnerable samples)."""
    by_cwe = {}
    for p in predictions:
        if p.get("true_label") != 1:
            continue
        cwe = p.get("true_cwe", "unknown") or "unknown"
        if cwe not in by_cwe:
            by_cwe[cwe] = {"total": 0, "detected": 0}
        by_cwe[cwe]["total"] += 1
        if p.get("predicted_vuln"):
            by_cwe[cwe]["detected"] += 1
    for cwe, d in by_cwe.items():
        d["recall"] = round(d["detected"] / d["total"], 4) if d["total"] else 0
    return by_cwe


async def run_evaluation(
    test_samples: List[dict],
    config_name: str,
    output_path: Path,
    limit: Optional[int] = None,
    resume: bool = True,
    confidence_threshold: float = 0.5,
):
    from pipeline.coordinator import Coordinator

    cfg = CONFIG_PRESETS[config_name]
    # Ensure all configs have all keys (default False) for forward compatibility
    cfg = {
        "enable_router": False, "enable_hybrid": False, "enable_hyde": False,
        "enable_reranker": False, "enable_crag": False, "enable_verifier": False,
        "enable_voting": False, "enable_debate": False, "enable_kl_rag": False,
        **cfg,
    }
    print(f"\nConfig: {config_name}")
    print(f"  {cfg}")
    print(f"  Confidence threshold (predict vuln if conf >= X): {confidence_threshold}")

    coord = Coordinator(
        llm=get_llm(),
        chroma_persist_dir=str(ROOT / "data" / "chroma_db"),
        kl_chroma_persist_dir=str(ROOT / "data" / "chroma_kl_db"),
        rag_corpus_path=str(ROOT / "data" / "rag_corpus_v2_filtered.jsonl"),
        retrieval_k=3,
        use_local_reranker=False,
        **cfg,
    )

    # Resume from previous run if exists
    predictions = []
    done_ids = set()
    if resume and output_path.exists():
        try:
            existing = json.loads(output_path.read_text(encoding="utf-8"))
            predictions = existing.get("predictions", [])
            done_ids = {p["sample_id"] for p in predictions}
            print(f"  Resuming: {len(done_ids)} samples already done")
        except Exception:
            pass

    samples_to_run = [s for s in test_samples if s.get("id") not in done_ids]
    if limit:
        # limit applies to TOTAL (done + pending), not just pending
        remaining_quota = max(0, limit - len(done_ids))
        samples_to_run = samples_to_run[:remaining_quota]

    print(f"  Running {len(samples_to_run)} samples...")

    start = time.time()
    for i, sample in enumerate(samples_to_run):
        sample_id = sample.get("id", f"unknown_{i}")
        code = sample.get("vulnerable_code", "") or sample.get("code", "")
        true_label = sample.get("label", 0)
        true_cwe = sample.get("cwe_id")
        language = sample.get("language", "C++")

        try:
            t0 = time.time()
            result = await coord.run(code, language=language)
            elapsed = time.time() - t0

            verdict = result["verdict"]
            raw_pred = bool(verdict.get("has_vulnerability"))
            confidence = verdict.get("confidence", 0)
            # Apply confidence threshold: only count as positive if conf >= threshold
            final_pred = raw_pred and confidence >= confidence_threshold

            pred_record = {
                "sample_id": sample_id,
                "true_label": true_label,
                "true_cwe": true_cwe,
                "predicted_vuln": final_pred,
                "raw_predicted_vuln": raw_pred,
                "predicted_cwe": verdict.get("vulnerability_type"),
                "confidence": confidence,
                "router_cwe": result["router"]["primary"],
                "rag_quality": result.get("rag_quality"),
                "rag_doc_count": result.get("rag_doc_count", 0),
                "verification_status": verdict.get("verification_status", "not_run"),
                "elapsed": round(elapsed, 2),
            }
        except Exception as e:
            pred_record = {
                "sample_id": sample_id,
                "true_label": true_label,
                "true_cwe": true_cwe,
                "predicted_vuln": False,
                "predicted_cwe": None,
                "confidence": 0,
                "error": str(e)[:200],
            }

        predictions.append(pred_record)

        if (i + 1) % 5 == 0 or i == len(samples_to_run) - 1:
            metrics = compute_metrics(predictions)
            avg_time = (time.time() - start) / (i + 1)
            eta = avg_time * (len(samples_to_run) - i - 1)
            print(f"  [{i+1}/{len(samples_to_run)}] "
                  f"P={metrics['precision']:.3f} R={metrics['recall']:.3f} F1={metrics['f1']:.3f} "
                  f"avg={avg_time:.1f}s ETA={eta/60:.1f}min")

            # Save intermediate
            _save_results(output_path, predictions, config_name, len(test_samples))

    metrics = compute_metrics(predictions)
    cwe_recall = cwe_breakdown(predictions)
    _save_results(output_path, predictions, config_name, len(test_samples), metrics, cwe_recall)

    print(f"\n=== Final Results ({config_name}) ===")
    print(f"  Total: {metrics['total']}")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1:        {metrics['f1']:.4f}")
    print(f"  Confusion: TP={metrics['tp']} FP={metrics['fp']} TN={metrics['tn']} FN={metrics['fn']}")
    if cwe_recall:
        print(f"\nPer-CWE recall:")
        for cwe, d in sorted(cwe_recall.items()):
            print(f"  {cwe}: {d['detected']}/{d['total']} = {d['recall']:.2f}")
    return metrics


def _save_results(path, predictions, config_name, total_samples, metrics=None, cwe_recall=None):
    out = {
        "config": config_name,
        "total_samples": total_samples,
        "completed": len(predictions),
        "predictions": predictions,
    }
    if metrics:
        out["metrics"] = metrics
    if cwe_recall:
        out["cwe_recall"] = cwe_recall
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", type=str, default="data/test_v2_filtered.jsonl")
    parser.add_argument("--config", type=str, default="full",
                        choices=list(CONFIG_PRESETS.keys()))
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--output", type=str, default=None)
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--threshold", type=float, default=0.5,
                        help="Confidence threshold to predict vulnerable (default 0.5)")
    args = parser.parse_args()

    test_path = ROOT / args.test
    if not test_path.exists():
        print(f"ERROR: {test_path} not found")
        return

    output_path = Path(args.output) if args.output else (
        ROOT / "experiments" / f"eval_{args.config}_{test_path.stem}.json"
    )

    samples = load_jsonl(test_path)
    print(f"Loaded {len(samples)} samples from {test_path}")
    asyncio.run(run_evaluation(
        test_samples=samples,
        config_name=args.config,
        output_path=output_path,
        limit=args.limit,
        resume=not args.no_resume,
        confidence_threshold=args.threshold,
    ))


if __name__ == "__main__":
    main()
