# [B5: CRAG纠正性检索] LLM-as-Judge评估检索质量，质量低时改写查询重试（最大2轮），防止检索到无关案例
"""Corrective RAG (CRAG) - retrieval quality evaluation and correction.

After retrieval, an LLM-based evaluator judges whether the retrieved cases
are actually relevant to the query code. If quality is low, the system
retries with relaxed filters or rewritten queries.

Reference: Yan et al., "Corrective Retrieval Augmented Generation", 2024
"""

from enum import Enum
from typing import List, Optional

from langchain_core.documents import Document
from langchain_core.language_models import BaseChatModel
from langchain_core.prompts import ChatPromptTemplate


class RetrievalQuality(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


EVALUATOR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a retrieval quality evaluator for code vulnerability detection.

Given a query code snippet and a set of retrieved vulnerability cases,
judge whether the retrieved cases are relevant and useful for analyzing the query code.

Scoring criteria:
- HIGH: Most cases share the same vulnerability pattern as potential issues in the query code
- MEDIUM: Some cases are relevant but others are noise
- LOW: Cases are mostly irrelevant to the query code's potential vulnerabilities

Output ONLY one word: HIGH, MEDIUM, or LOW"""),
    ("user", """Query code:
```
{query_code}
```

Retrieved cases (summarized):
{cases_summary}

Relevance judgment:"""),
])


class CRAGEvaluator:
    """Evaluates retrieval quality and decides whether to retry."""

    def __init__(self, llm: BaseChatModel, low_threshold: float = 0.4):
        self.llm = llm
        self.chain = EVALUATOR_PROMPT | self.llm
        self.low_threshold = low_threshold

    async def evaluate(
        self,
        query_code: str,
        documents: List[Document],
    ) -> RetrievalQuality:
        """Judge retrieval quality."""
        if not documents:
            return RetrievalQuality.LOW

        cases_summary = self._summarize_cases(documents)
        response = await self.chain.ainvoke({
            "query_code": query_code[:2000],
            "cases_summary": cases_summary,
        })
        text = response.content.strip().upper()

        if "HIGH" in text:
            return RetrievalQuality.HIGH
        elif "MEDIUM" in text:
            return RetrievalQuality.MEDIUM
        return RetrievalQuality.LOW

    def _summarize_cases(self, documents: List[Document]) -> str:
        summaries = []
        for i, doc in enumerate(documents[:5]):
            cwe = doc.metadata.get("cwe_id", "unknown")
            repo = doc.metadata.get("repo", "unknown")
            code_preview = doc.page_content[:200].replace("\n", " ")
            summaries.append(f"Case {i+1} [{cwe}, {repo}]: {code_preview}...")
        return "\n\n".join(summaries)


class CRAGPipeline:
    """Full CRAG pipeline: retrieve -> evaluate -> correct if needed."""

    def __init__(self, evaluator: CRAGEvaluator, max_retries: int = 2):
        self.evaluator = evaluator
        self.max_retries = max_retries

    async def retrieve_with_correction(
        self,
        query_code: str,
        retriever,
        k: int = 5,
        cwe_filter: Optional[str] = None,
    ) -> dict:
        """Retrieve, evaluate, and retry if quality is low.

        Returns:
            {
                "documents": List[Document],
                "quality": RetrievalQuality,
                "attempts": int,
                "cwe_filter_used": Optional[str]
            }
        """
        current_filter = cwe_filter

        for attempt in range(1, self.max_retries + 1):
            if hasattr(retriever, "retrieve"):
                if current_filter:
                    docs = await retriever.retrieve(
                        query_code, k=k, cwe_filter=current_filter
                    )
                else:
                    docs = await retriever.retrieve(query_code, k=k)
            else:
                docs = retriever.search(query_code, k=k, cwe_filter=current_filter)

            quality = await self.evaluator.evaluate(query_code, docs)

            if quality in (RetrievalQuality.HIGH, RetrievalQuality.MEDIUM):
                return {
                    "documents": docs,
                    "quality": quality,
                    "attempts": attempt,
                    "cwe_filter_used": current_filter,
                }

            # Correction strategy: relax filter on retry
            if current_filter is not None:
                current_filter = None
            else:
                break

        return {
            "documents": docs,
            "quality": RetrievalQuality.LOW,
            "attempts": self.max_retries,
            "cwe_filter_used": current_filter,
        }
