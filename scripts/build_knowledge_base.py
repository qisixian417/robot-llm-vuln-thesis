# [数据准备] KL-RAG知识库构建：用LLM将RAG语料中每条漏洞代码提炼为functional_semantics/root_cause/trigger/fix_pattern
#!/usr/bin/env python3
"""Build a Knowledge-Level RAG corpus from the existing code-level corpus.

For each vulnerable code sample, extract structured knowledge via LLM:
- functional_semantics: what the function is supposed to do
- root_cause: why this code is vulnerable
- trigger_condition: what input/state triggers the vulnerability
- fix_pattern: how the vulnerability should be fixed

Inspired by Vul-RAG (Du et al., 2024).

Usage:
    # Test on 5 samples first to validate prompt quality
    python scripts/build_knowledge_base.py --test --limit 5

    # Full extraction on all 319 RAG entries
    python scripts/build_knowledge_base.py
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
        openai_api_base=os.getenv(
            "LLM_BASE_URL",
            "https://dashscope.aliyuncs.com/compatible-mode/v1",
        ),
        temperature=0.1,
    )


KNOWLEDGE_PROMPT = """You are a senior security analyst. Analyze the following vulnerable code snippet and extract structured knowledge.

The vulnerability is classified as: {cwe_id}

Extract knowledge along 4 dimensions. Be specific, technical, and concise.

1. **functional_semantics**: What is this function/code SUPPOSED to do? (1 sentence, action verb)
2. **root_cause**: Why is this code unsafe? Explain the underlying flaw mechanism. (2 sentences max, technical detail)
3. **trigger_condition**: What input pattern, attacker-controlled state, or runtime condition triggers the vulnerability? (1 sentence, concrete)
4. **fix_pattern**: How should this be fixed? Provide an actionable fix strategy. (1-2 sentences, concrete API or check)

Output STRICTLY the following JSON, no markdown fences, no preamble:
{{
  "functional_semantics": "...",
  "root_cause": "...",
  "trigger_condition": "...",
  "fix_pattern": "..."
}}

Vulnerable code ({language}):
```
{code}
```
"""


def parse_knowledge_response(raw: str) -> Optional[Dict[str, str]]:
    text = raw.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        if lines[-1].startswith("```"):
            text = "\n".join(lines[1:-1])
        else:
            text = "\n".join(lines[1:])

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if 0 <= start < end:
            try:
                data = json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                return None
        else:
            return None

    required = ("functional_semantics", "root_cause", "trigger_condition", "fix_pattern")
    if not all(k in data for k in required):
        return None
    if not all(isinstance(data[k], str) and data[k].strip() for k in required):
        return None
    return {k: data[k].strip() for k in required}


async def extract_knowledge(llm, code: str, cwe_id: str, language: str) -> Optional[Dict[str, str]]:
    prompt = KNOWLEDGE_PROMPT.format(
        code=code[:2500],
        cwe_id=cwe_id or "Unknown",
        language=language or "C++",
    )
    try:
        response = await llm.ainvoke(prompt)
        return parse_knowledge_response(response.content)
    except Exception as e:
        print(f"    [ERROR] {e}")
        return None


def load_jsonl(path: Path) -> List[dict]:
    samples = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def save_jsonl(items: List[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=str, default="data/rag_corpus_v2_filtered.jsonl")
    parser.add_argument("--output", type=str, default="data/rag_knowledge_v1.jsonl")
    parser.add_argument("--test", action="store_true",
                        help="Test mode: print extracted knowledge for inspection")
    parser.add_argument("--limit", type=int, default=None,
                        help="Limit number of entries to process")
    parser.add_argument("--no-resume", action="store_true",
                        help="Don't resume from previous output")
    args = parser.parse_args()

    input_path = ROOT / args.input
    output_path = ROOT / args.output

    if not input_path.exists():
        print(f"ERROR: Input not found: {input_path}")
        return

    samples = load_jsonl(input_path)
    print(f"Loaded {len(samples)} samples from {input_path}")

    # Resume support
    done = []
    done_ids = set()
    if not args.no_resume and output_path.exists():
        try:
            done = load_jsonl(output_path)
            done_ids = {d["id"] for d in done}
            print(f"Resuming: {len(done_ids)} already processed")
        except Exception:
            pass

    pending = [s for s in samples if s.get("id") not in done_ids]
    if args.limit:
        pending = pending[:args.limit]

    print(f"Processing {len(pending)} samples...")
    print(f"Mode: {'TEST (will print)' if args.test else 'BATCH'}")
    print()

    llm = get_llm()
    results = list(done)
    failed = 0
    start = time.time()

    for i, sample in enumerate(pending):
        sample_id = sample.get("id", f"unknown_{i}")
        code = sample.get("vulnerable_code") or sample.get("code") or ""
        cwe_id = sample.get("cwe_id") or "Unknown"
        language = sample.get("language") or "C++"

        if not code:
            print(f"  [{i+1}/{len(pending)}] SKIP {sample_id} (empty code)")
            continue

        knowledge = await extract_knowledge(llm, code, cwe_id, language)

        if knowledge is None:
            failed += 1
            print(f"  [{i+1}/{len(pending)}] FAIL {sample_id} (parse error)")
            continue

        # Build new entry preserving original metadata + adding knowledge
        new_entry = {
            "id": sample_id,
            "cwe_id": cwe_id,
            "language": language,
            "repo": sample.get("repo", ""),
            "ros_component": sample.get("ros_component", ""),
            "ros_version": sample.get("ros_version", ""),
            **knowledge,
            "raw_code": code,  # keep for fallback / debugging
        }
        results.append(new_entry)

        if args.test:
            print(f"\n[{i+1}] {sample_id} ({cwe_id}, {language})")
            print(f"  Code: {code[:150]}{'...' if len(code) > 150 else ''}")
            print(f"  >> functional_semantics: {knowledge['functional_semantics']}")
            print(f"  >> root_cause:           {knowledge['root_cause']}")
            print(f"  >> trigger_condition:    {knowledge['trigger_condition']}")
            print(f"  >> fix_pattern:          {knowledge['fix_pattern']}")
        else:
            elapsed = time.time() - start
            avg = elapsed / (i + 1)
            eta = avg * (len(pending) - i - 1)
            if (i + 1) % 5 == 0 or i == len(pending) - 1:
                print(f"  [{i+1}/{len(pending)}] OK  avg={avg:.1f}s  ETA={eta/60:.1f}min  failed={failed}")

        # Periodic save
        if (i + 1) % 10 == 0:
            save_jsonl(results, output_path)

    save_jsonl(results, output_path)
    print(f"\nDone. Saved {len(results)} entries to {output_path}")
    print(f"Failed: {failed}")


if __name__ == "__main__":
    asyncio.run(main())
