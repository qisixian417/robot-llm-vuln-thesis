# [B1: Hybrid混合检索] BM25+Dense双路召回，用RRF算法融合排名，提供比单一检索更丰富的候选集
"""Hybrid retriever combining BM25 (sparse) and Dense (vector) retrieval.

Fusion via Reciprocal Rank Fusion (RRF), a standard technique that assigns
each result a score of 1/(k+rank) and sums across retrievers.
"""

from typing import Dict, List, Optional

from langchain_core.documents import Document

from rag.bm25_retriever import BM25Retriever
from rag.retriever import RAGRetriever


DEFAULT_RRF_K = 60


class HybridRetriever:
    """Fuse BM25 + Dense retrieval using Reciprocal Rank Fusion."""

    def __init__(
        self,
        dense_retriever: RAGRetriever,
        bm25_retriever: BM25Retriever,
        rrf_k: int = DEFAULT_RRF_K,
    ):
        self.dense = dense_retriever
        self.bm25 = bm25_retriever
        self.rrf_k = rrf_k

    async def retrieve(
        self,
        query: str,
        k: int = 5,
        dense_k: int = 20,
        bm25_k: int = 20,
        cwe_filter: Optional[str] = None,
    ) -> List[Document]:
        """Hybrid search with RRF fusion.

        Args:
            query: input code snippet
            k: final number of results to return
            dense_k: candidates from dense retrieval
            bm25_k: candidates from BM25 retrieval
            cwe_filter: optional CWE type filter for BM25
        """
        dense_results = await self.dense.retrieve(query, k=dense_k)
        bm25_results = self.bm25.search(query, k=bm25_k, cwe_filter=cwe_filter)

        fused = self._rrf_fuse(dense_results, bm25_results, k)
        return fused

    def _rrf_fuse(
        self,
        dense_docs: List[Document],
        bm25_docs: List[Document],
        k: int,
    ) -> List[Document]:
        """Reciprocal Rank Fusion."""
        scores: Dict[str, float] = {}
        doc_map: Dict[str, Document] = {}

        for rank, doc in enumerate(dense_docs):
            doc_id = self._doc_key(doc)
            scores[doc_id] = scores.get(doc_id, 0) + 1 / (self.rrf_k + rank + 1)
            doc.metadata["source_dense"] = True
            doc_map[doc_id] = doc

        for rank, doc in enumerate(bm25_docs):
            doc_id = self._doc_key(doc)
            scores[doc_id] = scores.get(doc_id, 0) + 1 / (self.rrf_k + rank + 1)
            if doc_id in doc_map:
                doc_map[doc_id].metadata["source_bm25"] = True
            else:
                doc.metadata["source_bm25"] = True
                doc_map[doc_id] = doc

        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        results: List[Document] = []
        for doc_id, score in ranked[:k]:
            doc = doc_map[doc_id]
            doc.metadata["rrf_score"] = round(score, 6)
            results.append(doc)
        return results

    @staticmethod
    def _doc_key(doc: Document) -> str:
        """Unique key for deduplication."""
        doc_id = doc.metadata.get("id")
        if doc_id:
            return str(doc_id)
        return str(hash(doc.page_content[:200]))
