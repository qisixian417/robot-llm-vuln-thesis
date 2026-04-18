import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.evaluate_rag_vs_norag import (  # noqa: E402
    CORPUS_PATH,
    TOP_K,
    build_bm25,
    build_dense_index,
    build_rag_messages,
    build_tfidf,
    compute_metrics,
    hybrid_retrieve,
    load_jsonl,
    parse_label,
)


load_dotenv(ROOT / ".env")

API_KEY = os.getenv("DASHSCOPE_API_KEY", "")
API_URL = os.getenv("LLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1") + "/chat/completions"


def extract_confidence(response: str) -> float:
    try:
        parsed = json.loads(response.strip())
        return float(parsed.get("confidence", 0.5))
    except Exception:
        return 0.5


def call_model(model: str, messages: List[Dict[str, str]], retries: int = 3) -> str:
    payload = json.dumps(
        {
            "model": model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": 1024,
        }
    ).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
    }

    last_error = ""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(API_URL, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=90) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"]
        except Exception as exc:
            last_error = str(exc)
            print(f"    API调用失败(第{attempt + 1}次): {exc}", flush=True)
            if attempt < retries - 1:
                time.sleep(5)
    raise RuntimeError(last_error or "unknown API error")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a robotics-RAG model on a custom dataset")
    parser.add_argument("--dataset", type=str, required=True, help="Dataset JSONL path")
    parser.add_argument("--model", type=str, default="qwen-plus", help="DashScope model name")
    parser.add_argument("--output", type=str, required=True, help="Output JSON path")
    parser.add_argument("--request-interval", type=float, default=1.5, help="Sleep between API calls")
    parser.add_argument("--limit", type=int, default=0, help="Only evaluate the first N samples")
    parser.add_argument("--corpus", type=str, default=str(CORPUS_PATH), help="RAG corpus JSONL path")
    args = parser.parse_args()

    if not API_KEY:
        raise RuntimeError("DASHSCOPE_API_KEY 未配置")

    dataset_path = ROOT / args.dataset if not Path(args.dataset).is_absolute() else Path(args.dataset)
    corpus_path = ROOT / args.corpus if not Path(args.corpus).is_absolute() else Path(args.corpus)
    output_path = ROOT / args.output if not Path(args.output).is_absolute() else Path(args.output)

    dataset_all = load_jsonl(dataset_path)
    dataset = dataset_all[: args.limit] if args.limit and args.limit > 0 else dataset_all
    corpus = load_jsonl(corpus_path)
    corpus_texts = [doc.get("content", "") for doc in corpus]

    print("=" * 72, flush=True)
    print(f"Robotics-RAG 模型评测: {args.model}", flush=True)
    print("=" * 72, flush=True)
    print(f"数据集: {dataset_path}", flush=True)
    print(f"知识库: {corpus_path}", flush=True)
    print(f"样本数: {len(dataset)} | 文档数: {len(corpus)}", flush=True)

    print("\n[1/2] 构建检索索引...", flush=True)
    bm25_index = build_bm25(corpus_texts)
    vocab_idx, idf_vals, tfidf_matrix = build_tfidf(corpus_texts)
    dense_model, dense_corpus_emb = build_dense_index(corpus_texts)
    print("索引构建完成。", flush=True)

    print("\n[2/2] 开始逐样本推理...", flush=True)
    true_labels: List[int] = []
    preds: List[int] = []
    confidences: List[float] = []
    rows: List[Dict[str, Any]] = []

    for idx, sample in enumerate(dataset, 1):
        code = sample.get("vulnerable_code", "")
        label = int(sample.get("label", 0))
        sample_id = sample.get("id", f"sample_{idx}")
        language = sample.get("language", "unknown")

        retrieved, debug_info = hybrid_retrieve(
            code,
            corpus,
            vocab_idx,
            idf_vals,
            tfidf_matrix,
            bm25_index,
            dense_model=dense_model,
            dense_corpus_emb=dense_corpus_emb,
            top_k=TOP_K,
            use_reranker=False,
            use_dynamic_topk=False,
        )
        retrieved_indices = [doc_idx for doc_idx, _ in retrieved]
        retrieved_docs = [corpus[doc_idx] for doc_idx in retrieved_indices]
        response = call_model(args.model, build_rag_messages(code, retrieved_docs))
        pred = parse_label(response)
        conf = extract_confidence(response)

        true_labels.append(label)
        preds.append(pred)
        confidences.append(conf)

        rows.append(
            {
                "id": sample_id,
                "language": language,
                "true_label": label,
                "pred": pred,
                "confidence": conf,
                "retrieved_doc_ids": [doc.get("id") for doc in retrieved_docs],
                "retrieval_debug": debug_info,
                "raw_response": response,
            }
        )

        print(
            f"[{idx:>3}/{len(dataset)}] {sample_id} | lang={language:<6} "
            f"| true={label} pred={pred} conf={conf:.2f} docs={[doc.get('id') for doc in retrieved_docs[:3]]}",
            flush=True,
        )
        if idx < len(dataset):
            time.sleep(args.request_interval)

    overall = compute_metrics(true_labels, preds)
    overall["avg_confidence"] = sum(confidences) / len(confidences) if confidences else 0.0

    output = {
        "config": {
            "dataset": str(dataset_path),
            "corpus": str(corpus_path),
            "model": args.model,
            "sample_size": len(dataset),
            "request_interval": args.request_interval,
            "top_k": TOP_K,
            "use_reranker": False,
            "use_dynamic_topk": False,
        },
        "overall": overall,
        "samples": rows,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print("\n" + "-" * 60, flush=True)
    print(
        f"overall -> f1={overall['f1']:.4f} acc={overall['accuracy']:.4f} "
        f"prec={overall['precision']:.4f} rec={overall['recall']:.4f}",
        flush=True,
    )
    print("-" * 60, flush=True)
    print(f"结果已保存到: {output_path}", flush=True)


if __name__ == "__main__":
    main()
