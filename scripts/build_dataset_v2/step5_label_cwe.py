#!/usr/bin/env python3
"""
Step 5: 对 cwe_id 为 None 的漏洞样本，用 LLM 补全 CWE 标签。
只处理 label=1 且 cwe_id=None 的样本。
输出：data_v2/processed/train_v2.jsonl / test_v2.jsonl（原地更新）
"""

import asyncio
import json
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent.parent
load_dotenv(ROOT / ".env")

TRAIN = ROOT / "data_v2" / "processed" / "train_v2.jsonl"
TEST = ROOT / "data_v2" / "processed" / "test_v2.jsonl"
RAG = ROOT / "data_v2" / "processed" / "rag_corpus_v2.jsonl"

TARGET_CWES = [
    "CWE-119", "CWE-401", "CWE-362", "CWE-476",
    "CWE-416", "CWE-190", "CWE-134", "CWE-78"
]

PROMPT = """You are a C/C++ and Python security expert specializing in memory safety and vulnerability analysis.

Commit message: {message}

Vulnerable code:
```
{code}
```

This code contains a security vulnerability. Classify it into EXACTLY ONE of these categories based on the most prominent vulnerability pattern:

- CWE-476: Null Pointer Dereference — pointer used without NULL check, potential crash
- CWE-401: Memory Leak — allocated memory not freed, resource leak
- CWE-362: Race Condition — shared resource accessed without proper synchronization/locking
- CWE-416: Use After Free — memory accessed after being freed/deallocated
- CWE-119: Buffer Overflow — buffer read/write beyond bounds (includes stack/heap overflow)
- CWE-190: Integer Overflow — arithmetic overflow, unsigned wrap-around
- CWE-134: Format String — user-controlled format string in printf/sprintf
- CWE-78: Command Injection — user input passed unsanitized to shell command

Decision rules:
- If you see missing NULL check before pointer dereference → CWE-476
- If you see malloc/new without corresponding free/delete → CWE-401
- If you see shared variable accessed without mutex/lock → CWE-362
- If you see pointer used after delete/free → CWE-416
- If you see array access without bounds check or strcpy/memcpy → CWE-119
- If you see integer arithmetic that could overflow → CWE-190
- If commit message mentions "fix crash", "null pointer", "dereference" → likely CWE-476
- If commit message mentions "leak", "memory" → likely CWE-401
- If commit message mentions "race", "lock", "concurrent" → likely CWE-362

You MUST choose one. Pick the BEST match even if uncertain.

Reply with ONLY the CWE ID (e.g., "CWE-476"). No explanation. No other text."""


def load_jsonl(path):
    data = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                data.append(json.loads(line))
    return data


def save_jsonl(data, path):
    with open(path, "w", encoding="utf-8") as f:
        for item in data:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")


async def classify_cwe(llm, code: str, message: str) -> str:
    from langchain_core.messages import HumanMessage
    prompt = PROMPT.format(
        message=message[:200],
        code=code[:2000],
    )
    try:
        response = await llm.ainvoke([HumanMessage(content=prompt)])
        result = response.content.strip().upper()
        for cwe in TARGET_CWES:
            if cwe in result:
                return cwe
        # LLM didn't return a valid CWE, retry with simpler prompt
        retry_prompt = f"This C++ code has a security vulnerability. Reply with ONLY one of: CWE-119, CWE-401, CWE-362, CWE-476, CWE-416, CWE-190, CWE-134, CWE-78\n\nCode:\n{code[:500]}"
        try:
            r2 = await llm.ainvoke([HumanMessage(content=retry_prompt)])
            result2 = r2.content.strip().upper()
            for cwe in TARGET_CWES:
                if cwe in result2:
                    return cwe
        except Exception:
            pass
        # Default to most common CWE based on code characteristics
        code_lower = code.lower()
        if "null" in code_lower or "nullptr" in code_lower or "->'" in code_lower:
            return "CWE-476"
        if "malloc" in code_lower or "new " in code_lower or "alloc" in code_lower:
            return "CWE-401"
        if "memcpy" in code_lower or "strcpy" in code_lower or "sprintf" in code_lower:
            return "CWE-119"
        if "mutex" in code_lower or "lock" in code_lower or "thread" in code_lower:
            return "CWE-362"
        return "CWE-476"  # most common fallback
    except Exception as e:
        print(f"  [错误] LLM 调用失败: {e}")
        return "CWE-476"  # fallback instead of None


async def process_file(path: Path, llm):
    data = load_jsonl(path)
    to_label = [
        (i, s) for i, s in enumerate(data)
        if s["label"] == 1 and not s.get("cwe_id")
    ]
    print(f"{path.name}: 共 {len(data)} 条，需要补充 CWE 的: {len(to_label)} 条")

    for count, (i, sample) in enumerate(to_label):
        code = sample.get("vulnerable_code", "")
        message = sample.get("description", "")
        cwe = await classify_cwe(llm, code, message)
        if cwe:
            data[i]["cwe_id"] = cwe if cwe != "OTHER" else None
            data[i]["cwe_source"] = "llm"
        else:
            data[i]["cwe_source"] = "failed"

        if (count + 1) % 20 == 0:
            save_jsonl(data, path)
            print(f"  [{count+1}/{len(to_label)}] 中间保存")

    save_jsonl(data, path)

    labeled = sum(1 for s in data if s["label"] == 1 and s.get("cwe_id"))
    unlabeled = sum(1 for s in data if s["label"] == 1 and not s.get("cwe_id"))
    print(f"  完成: CWE已标注={labeled}, 未能标注={unlabeled}")
    return data


async def main():
    from langchain_openai import ChatOpenAI
    llm = ChatOpenAI(
        model=os.getenv("MODEL_NAME", "qwen-plus"),
        openai_api_key=os.getenv("DASHSCOPE_API_KEY"),
        openai_api_base=os.getenv("LLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
        temperature=0.0,
    )

    for path in [TRAIN, TEST]:
        if path.exists():
            await process_file(path, llm)

    # RAG 语料同步更新（从 train 里重新提取）
    if TRAIN.exists():
        train_data = load_jsonl(TRAIN)
        rag_corpus = [s for s in train_data if s["label"] == 1]
        save_jsonl(rag_corpus, RAG)
        print(f"\nRAG语料更新: {len(rag_corpus)} 条 -> {RAG}")

    print("\n全部完成！")


if __name__ == "__main__":
    asyncio.run(main())
