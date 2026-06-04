# [B4: 重排器] 优先使用FlashRank(ONNX跨编码器，无需GPU)对候选文档精排；退化时使用LLMReranker（LLM打分）
"""Cross-Encoder reranker for retrieval results.

Supports three modes (in priority order):
1. FlashRank: lightweight ONNX cross-encoder, no GPU/torch required (recommended)
2. sentence-transformers CrossEncoder: higher quality but needs torch
3. LLM-based fallback: uses the project LLM to score relevance
"""

from typing import List, Optional, Tuple

from langchain_core.documents import Document
from langchain_core.language_models import BaseChatModel


class CrossEncoderReranker:
    """Rerank using FlashRank (ONNX, no torch) or sentence-transformers."""

    def __init__(self, model_name: str = "ms-marco-MiniLM-L-12-v2"):
        self._ranker = None
        self._mode = "none"
        self._load_model(model_name)

    def _load_model(self, model_name: str) -> None:
        # Try FlashRank first (no torch needed)
        try:
            import os
            from pathlib import Path
            from flashrank import Ranker
            cache_dir = str(Path(__file__).resolve().parent.parent / "data" / "flashrank_cache")
            os.makedirs(cache_dir, exist_ok=True)
            self._ranker = Ranker(model_name="ms-marco-MiniLM-L-12-v2", cache_dir=cache_dir)
            self._mode = "flashrank"
            print(f"[Reranker] Using FlashRank: ms-marco-MiniLM-L-12-v2")
            return
        except Exception as e:
            print(f"[Reranker] FlashRank not available ({e}), trying sentence-transformers...")

        # Fall back to sentence-transformers
        try:
            from sentence_transformers import CrossEncoder
            self._ranker = CrossEncoder(model_name)
            self._mode = "cross-encoder"
            print(f"[Reranker] Using CrossEncoder: {model_name}")
        except Exception as e:
            print(f"[Reranker] No local reranker available ({e}). Use LLMReranker instead.")
            self._mode = "none"

    def rerank(
        self,
        query: str,
        documents: List[Document],
        top_k: int = 5,
    ) -> List[Document]:
        if not documents:
            return []

        if self._mode == "flashrank":
            return self._rerank_flashrank(query, documents, top_k)
        elif self._mode == "cross-encoder":
            return self._rerank_crossencoder(query, documents, top_k)
        else:
            return documents[:top_k]

    def _rerank_flashrank(self, query: str, documents: List[Document], top_k: int):
        from flashrank import RerankRequest
        passages = [
            {"id": i, "text": doc.page_content[:512]}
            for i, doc in enumerate(documents)
        ]
        request = RerankRequest(query=query[:512], passages=passages)
        results = self._ranker.rerank(request)
        ranked_ids = [r["id"] for r in results[:top_k]]
        reranked = []
        for r in results[:top_k]:
            doc = documents[r["id"]]
            doc.metadata["reranker_score"] = float(r.get("score", 0))
            reranked.append(doc)
        return reranked

    def _rerank_crossencoder(self, query: str, documents: List[Document], top_k: int):
        pairs = [(query[:512], doc.page_content[:512]) for doc in documents]
        scores = self._ranker.predict(pairs)
        scored = sorted(zip(documents, scores), key=lambda x: x[1], reverse=True)
        result = []
        for doc, score in scored[:top_k]:
            doc.metadata["reranker_score"] = float(score)
            result.append(doc)
        return result


class LLMReranker:
    """Fallback reranker using LLM to score relevance (no local GPU needed)."""

    def __init__(self, llm: BaseChatModel):
        self.llm = llm

    async def rerank(
        self,
        query: str,
        documents: List[Document],
        top_k: int = 5,
    ) -> List[Document]:
        """Score each document's relevance to the query via LLM."""
        if not documents:
            return []
        if len(documents) <= top_k:
            return documents

        scored: List[Tuple[Document, float]] = []
        for doc in documents:
            score = await self._score_pair(query, doc.page_content)
            doc.metadata["reranker_score"] = score
            scored.append((doc, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [doc for doc, _ in scored[:top_k]]

    async def _score_pair(self, query: str, document: str) -> float:
        """Ask LLM to rate relevance 0-10."""
        prompt = (
            f"Rate the relevance of this vulnerability case to the query code.\n"
            f"Score from 0 (irrelevant) to 10 (highly relevant).\n"
            f"Output ONLY a number.\n\n"
            f"Query code:\n{query[:500]}\n\n"
            f"Vulnerability case:\n{document[:500]}\n\n"
            f"Relevance score:"
        )
        try:
            response = await self.llm.ainvoke(prompt)
            score = float(response.content.strip().split()[0])
            return min(max(score, 0), 10) / 10
        except (ValueError, IndexError):
            return 0.5
