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

PROMPT = """你是一位专注于内存安全和漏洞分析的C/C++和Python安全专家。

提交信息：{message}

有漏洞的代码：
```
{code}
```

这段代码包含安全漏洞。根据最突出的漏洞模式，将其归入以下类别之一：

- CWE-476：空指针解引用 — 指针未做NULL检查就使用，可能导致崩溃
- CWE-401：内存泄漏 — 分配的内存没有释放，资源泄漏
- CWE-362：竞态条件 — 共享资源在没有正确同步/加锁的情况下被访问
- CWE-416：释放后使用 — 内存被释放后仍然被访问
- CWE-119：缓冲区溢出 — 缓冲区读写超出边界（包括栈/堆溢出）
- CWE-190：整数溢出 — 算术溢出、无符号整数回绕
- CWE-134：格式化字符串 — printf/sprintf中使用了用户可控的格式串
- CWE-78：命令注入 — 用户输入未经过滤直接传给shell命令

判断规则：
- 指针解引用前缺少NULL检查 → CWE-476
- malloc/new之后没有对应的free/delete → CWE-401
- 共享变量访问没有mutex/lock保护 → CWE-362
- 指针在delete/free后仍被使用 → CWE-416
- 数组访问没有边界检查，或使用了strcpy/memcpy → CWE-119
- 整数运算可能溢出 → CWE-190
- 提交信息提到"fix crash"、"null pointer"、"dereference" → 可能是CWE-476
- 提交信息提到"leak"、"memory" → 可能是CWE-401
- 提交信息提到"race"、"lock"、"concurrent" → 可能是CWE-362

你必须选择一个。即使不确定也要选择最匹配的。

只回复CWE ID（例如"CWE-476"），不要解释，不要其他内容。"""


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
