# [C2: Detection Agent] 主检测模块：根据Router预判的CWE类型选用专用prompt，结合KL-RAG案例判断漏洞
"""Vulnerability Detector Agent - CWE-specific code analysis.

This is the core detection module. Given a code snippet and (optionally) a
predicted CWE type from Router Agent, it uses a CWE-specific prompt to
focus the LLM's attention on the most likely vulnerability pattern.

Refactored from a single generic prompt to support 9 specialized prompts.
"""

import json
from typing import Dict, Any, List, Optional

from langchain_core.language_models import BaseChatModel

from agents.cwe_prompts import get_prompt_for_cwe


class VulnDetectorAgent:
    """CWE-aware vulnerability detection agent."""

    def __init__(self, llm: BaseChatModel, rag_retriever=None):
        self.llm = llm
        self.rag_retriever = rag_retriever

    async def detect(
        self,
        code: str,
        cwe_hint: Optional[str] = None,
        rag_documents: Optional[List] = None,
    ) -> Dict[str, Any]:
        """Detect vulnerability in code.

        Args:
            code: code snippet to analyze
            cwe_hint: optional CWE type predicted by Router Agent
                     (None or "OTHER" → generic prompt)
            rag_documents: pre-retrieved RAG context (optional;
                          if None, falls back to self.rag_retriever)
        """
        rag_docs = rag_documents or []
        if not rag_docs and self.rag_retriever:
            if cwe_hint and cwe_hint != "OTHER":
                try:
                    rag_docs = await self.rag_retriever.retrieve(code, k=5, cwe_filter=cwe_hint)
                except TypeError:
                    rag_docs = await self.rag_retriever.retrieve(code, k=5)
            else:
                rag_docs = await self.rag_retriever.retrieve(code, k=5)

        context = self._format_context(rag_docs)

        numbered_code = "\n".join(
            f"L{i+1}: {line}" for i, line in enumerate(code.splitlines())
        )

        prompt = get_prompt_for_cwe(cwe_hint or "OTHER")
        chain = prompt | self.llm
        response = await chain.ainvoke({
            "code": numbered_code,
            "context": context,
        })

        result = self._parse_response(response.content)

        result["retrieved_knowledge"] = [
            {"content": doc.page_content[:500], "metadata": doc.metadata}
            for doc in rag_docs
        ]
        result["cwe_hint_used"] = cwe_hint or "OTHER"

        return result

    def _format_context(self, docs: List) -> str:
        if not docs:
            return "No relevant historical cases found."
        parts = []
        for i, doc in enumerate(docs):
            content = getattr(doc, "page_content", str(doc))
            metadata = getattr(doc, "metadata", {})
            cwe = metadata.get("cwe_id", "?")
            repo = metadata.get("repo", "?")
            parts.append(f"Case {i+1} [{cwe} from {repo}]:\n{content[:500]}")
        return "\n\n".join(parts)

    def _parse_response(self, raw_text: str) -> Dict[str, Any]:
        text = raw_text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].startswith("```") else lines[1:])

        try:
            result = json.loads(text)
        except json.JSONDecodeError:
            try:
                start = text.find("{")
                end = text.rfind("}")
                if start >= 0 and end > start:
                    result = json.loads(text[start:end+1])
                else:
                    raise ValueError("No JSON found")
            except (json.JSONDecodeError, ValueError):
                return {
                    "has_vulnerability": False,
                    "vulnerability_type": None,
                    "reason": "Failed to parse LLM output",
                    "confidence": 0.0,
                    "vulnerable_lines": [],
                }

        result.setdefault("has_vulnerability", False)
        result.setdefault("vulnerability_type", None)
        result.setdefault("reason", "")
        result.setdefault("confidence", 0.5)
        result.setdefault("vulnerable_lines", [])

        try:
            result["confidence"] = max(0.0, min(1.0, float(result["confidence"])))
        except (TypeError, ValueError):
            result["confidence"] = 0.5

        return result
