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

from scripts.evaluate_rag_vs_norag import (
    compute_metrics,
    load_jsonl,
    parse_label,
    SYSTEM_PROMPT,
)


load_dotenv(ROOT / ".env")

API_KEY = os.getenv("DASHSCOPE_API_KEY", "")
API_URL = os.getenv("LLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1") + "/chat/completions"


def build_no_rag_messages(code: str) -> List[Dict[str, str]]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"请分析以下代码是否存在安全漏洞：\n\n```cpp\n{code}\n```"},
    ]


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
            print(f"    API调用失败(第{attempt + 1}次): {exc}")
            if attempt < retries - 1:
                time.sleep(5)
    raise RuntimeError(last_error or "unknown API error")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a no-RAG model on a custom dataset")
    parser.add_argument("--dataset", type=str, required=True, help="Dataset JSONL path")
    parser.add_argument("--model", type=str, default="qwen-plus", help="DashScope model name")
    parser.add_argument("--output", type=str, required=True, help="Output JSON path")
    parser.add_argument("--request-interval", type=float, default=1.5, help="Sleep between API calls")
    parser.add_argument("--limit", type=int, default=0, help="Only evaluate the first N samples")
    args = parser.parse_args()

    if not API_KEY:
        raise RuntimeError("DASHSCOPE_API_KEY 未配置")

    dataset_path = ROOT / args.dataset if not Path(args.dataset).is_absolute() else Path(args.dataset)
    output_path = ROOT / args.output if not Path(args.output).is_absolute() else Path(args.output)

    dataset_all = load_jsonl(dataset_path)
    dataset = dataset_all[: args.limit] if args.limit and args.limit > 0 else dataset_all

    print("=" * 72)
    print(f"No-RAG 模型评测: {args.model}")
    print("=" * 72)
    print(f"数据集: {dataset_path}")
    print(f"样本数: {len(dataset)}")

    true_labels: List[int] = []
    preds: List[int] = []
    confidences: List[float] = []
    rows: List[Dict[str, Any]] = []

    for idx, sample in enumerate(dataset, 1):
        code = sample.get("vulnerable_code", "")
        label = int(sample.get("label", 0))
        sample_id = sample.get("id", f"sample_{idx}")
        language = sample.get("language", "unknown")

        response = call_model(args.model, build_no_rag_messages(code))
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
                "raw_response": response,
            }
        )

        print(
            f"[{idx:>3}/{len(dataset)}] {sample_id} | lang={language:<6} "
            f"| true={label} pred={pred} conf={conf:.2f}"
        )
        if idx < len(dataset):
            time.sleep(args.request_interval)

    overall = compute_metrics(true_labels, preds)
    overall["avg_confidence"] = sum(confidences) / len(confidences) if confidences else 0.0

    output = {
        "config": {
            "dataset": str(dataset_path),
            "model": args.model,
            "sample_size": len(dataset),
            "request_interval": args.request_interval,
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
