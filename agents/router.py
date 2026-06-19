# [C1: Router Agent] CWE类型预判：在RAG检索前预测代码可能含哪种CWE，用于定向检索（配合KL-RAG有效，单独使用反而降低F1）
"""Router Agent - CWE type classification for routing to specialized detection.

Predicts the most likely CWE type(s) of a code snippet BEFORE detection,
enabling targeted RAG retrieval and CWE-specific prompts.
"""

import json
from typing import Dict, Any, List, Optional

from langchain_core.language_models import BaseChatModel
from langchain_core.prompts import ChatPromptTemplate


ROUTER_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """你是一个漏洞分类专家。给定一段代码，预测它最可能包含哪种CWE类型的漏洞。

可选的CWE类型：
- CWE-119: 缓冲区溢出（strcpy、memcpy、固定大小数组、没有边界检查）
- CWE-476: 空指针解引用（指针使用前没有NULL检查）
- CWE-401: 内存泄漏（malloc/new之后没有在所有路径上free/delete）
- CWE-362: 竞态条件（共享变量、多线程、没有加锁）
- CWE-416: 释放后使用（free/delete之后仍然使用指针）
- CWE-190: 整数溢出（整数运算没有边界检查）
- CWE-134: 格式化字符串（printf使用了用户可控的格式串）
- CWE-78: 命令注入（system/exec/popen使用了字符串拼接）

判断规则：
- strcpy/strcat/sprintf + 固定缓冲区 → CWE-119
- system()/exec()/popen() + 字符串拼接 → CWE-78
- new/malloc但错误路径没有delete/free → CWE-401
- 指针解引用前没有if(ptr)检查 → CWE-476
- printf(变量) 而不是 printf("%s", 变量) → CWE-134
- 共享变量 + 线程/回调 + 没有mutex → CWE-362
- delete/free之后继续使用 → CWE-416
- 算术运算没有溢出检查 → CWE-190

如果代码看起来安全或无法确定，输出"OTHER"。

只输出JSON，不要其他内容：
{{"primary": "CWE-XXX", "secondary": "CWE-YYY或null", "confidence": 0.0-1.0}}"""),
    ("user", "代码：\n```\n{code}\n```"),
])


class RouterAgent:
    """Classifies code into CWE type for downstream routing."""

    VALID_CWES = {
        "CWE-119", "CWE-476", "CWE-401", "CWE-362",
        "CWE-416", "CWE-190", "CWE-134", "CWE-78", "OTHER",
    }

    def __init__(self, llm: BaseChatModel):
        self.llm = llm
        self.chain = ROUTER_PROMPT | self.llm

    async def route(self, code: str) -> Dict[str, Any]:
        """Predict CWE type(s) for the given code.

        Returns:
            {
                "primary": "CWE-XXX",
                "secondary": "CWE-YYY" or None,
                "confidence": float,
                "use_filter": bool  (True if confidence high enough to filter RAG)
            }
        """
        response = await self.chain.ainvoke({"code": code[:3000]})

        try:
            result = json.loads(response.content.strip())
        except json.JSONDecodeError:
            return self._fallback(response.content)

        primary = result.get("primary", "OTHER")
        if primary not in self.VALID_CWES:
            primary = "OTHER"

        secondary = result.get("secondary")
        if secondary and secondary not in self.VALID_CWES:
            secondary = None

        confidence = float(result.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))

        return {
            "primary": primary,
            "secondary": secondary,
            "confidence": confidence,
            "use_filter": confidence >= 0.6 and primary != "OTHER",
        }

    def _fallback(self, raw_text: str) -> Dict[str, Any]:
        """Parse non-JSON response."""
        text = raw_text.upper()
        for cwe in self.VALID_CWES:
            if cwe in text:
                return {
                    "primary": cwe,
                    "secondary": None,
                    "confidence": 0.4,
                    "use_filter": False,
                }
        return {
            "primary": "OTHER",
            "secondary": None,
            "confidence": 0.3,
            "use_filter": False,
        }
