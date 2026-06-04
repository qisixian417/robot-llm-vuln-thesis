# [B1: BM25稀疏检索] 关键词精确匹配检索，与Dense向量检索互补，用于HybridRetriever的BM25通道
"""BM25 sparse retriever - keyword-based retrieval complementing dense vector search.

BM25 excels at exact term matching (function names, CWE IDs, API names),
which dense embedding models often dilute via semantic generalization.
"""

import json
import re
from pathlib import Path
from typing import List, Optional

from langchain_core.documents import Document
from rank_bm25 import BM25Okapi

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CORPUS_PATH = ROOT / "data" / "rag_corpus_v2.jsonl"


def code_tokenize(text: str) -> List[str]:
    """Code-aware tokenizer.

    Strategy:
    - Split on non-alphanumeric chars (preserves identifiers)
    - Split CamelCase / snake_case
    - Lowercase
    - Drop tokens shorter than 2 chars and pure-numeric tokens
    """
    if not text:
        return []
    raw = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\d+", text)
    tokens: List[str] = []
    for t in raw:
        sub = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", t)
        sub = sub.replace("_", " ")
        for piece in sub.split():
            piece = piece.lower()
            if len(piece) >= 2 and not piece.isdigit():
                tokens.append(piece)
    return tokens


class BM25Retriever:
    """In-memory BM25 retriever over RAG corpus."""

    def __init__(self, corpus_path: Optional[Path] = None):
        self.corpus_path = Path(corpus_path) if corpus_path else DEFAULT_CORPUS_PATH
        self._bm25: Optional[BM25Okapi] = None
        self._documents: List[Document] = []
        self._tokenized_corpus: List[List[str]] = []
        if self.corpus_path.exists():
            self._build_index()

    def _build_index(self) -> None:
        with open(self.corpus_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                item = json.loads(line)
                content = (
                    item.get("vulnerable_code")
                    or item.get("code")
                    or item.get("content")
                    or ""
                )
                if not content:
                    continue
                metadata = {
                    "id": item.get("id"),
                    "cwe_id": item.get("cwe_id"),
                    "language": item.get("language"),
                    "repo": item.get("repo"),
                    "ros_component": item.get("ros_component"),
                    "ros_version": item.get("ros_version"),
                }
                metadata = {k: v for k, v in metadata.items() if v is not None}
                self._documents.append(Document(page_content=content, metadata=metadata))
                self._tokenized_corpus.append(code_tokenize(content))

        if self._tokenized_corpus:
            self._bm25 = BM25Okapi(self._tokenized_corpus)
        print(f"[BM25] Indexed {len(self._documents)} documents from {self.corpus_path}")

    def is_ready(self) -> bool:
        return self._bm25 is not None and len(self._documents) > 0

    def count(self) -> int:
        return len(self._documents)

    def search(
        self,
        query: str,
        k: int = 5,
        cwe_filter: Optional[str] = None,
    ) -> List[Document]:
        """Top-k BM25 retrieval, optionally filtered by CWE."""
        if not self.is_ready():
            return []
        tokens = code_tokenize(query)
        if not tokens:
            return []
        scores = self._bm25.get_scores(tokens)
        ranked = sorted(
            range(len(scores)),
            key=lambda i: scores[i],
            reverse=True,
        )
        results: List[Document] = []
        for idx in ranked:
            if scores[idx] <= 0:
                break
            doc = self._documents[idx]
            if cwe_filter and doc.metadata.get("cwe_id") != cwe_filter:
                continue
            doc.metadata["bm25_score"] = float(scores[idx])
            results.append(doc)
            if len(results) >= k:
                break
        return results
