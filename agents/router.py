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
    ("system", """You are a vulnerability classifier. Given a code snippet,
predict which CWE type it MOST LIKELY contains (or could contain).

Available CWE types:
- CWE-119: Buffer Overflow (strcpy, memcpy, fixed-size arrays, no bounds check)
- CWE-476: NULL Pointer Dereference (pointer used without NULL check)
- CWE-401: Memory Leak (malloc/new without free/delete on all paths)
- CWE-362: Race Condition (shared variables, multiple threads, no locking)
- CWE-416: Use After Free (pointer used after free/delete)
- CWE-190: Integer Overflow (arithmetic on int without bounds check)
- CWE-134: Format String (printf with user-controlled format)
- CWE-78: Command Injection (system/exec/popen with string concatenation)

Pattern hints:
- strcpy/strcat/sprintf + fixed buffer → CWE-119
- system()/exec()/popen() + string concat → CWE-78
- new/malloc without delete/free on error path → CWE-401
- pointer dereference without if(ptr) check → CWE-476
- printf(variable) instead of printf("%s", variable) → CWE-134
- shared variable + thread/callback + no mutex → CWE-362
- delete/free then use → CWE-416
- arithmetic without overflow check → CWE-190

If the code appears safe or you are unsure, output "OTHER".

Output JSON only:
{{"primary": "CWE-XXX", "secondary": "CWE-YYY or null", "confidence": 0.0-1.0}}"""),
    ("user", "Code:\n```\n{code}\n```"),
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
