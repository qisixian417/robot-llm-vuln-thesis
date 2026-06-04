# [集成测试] 测试B组RAG模块（BM25/Hybrid/Filter/HyDE/Reranker/CRAG）是否正常工作
#!/usr/bin/env python3
"""Integration test for B-group RAG enhancement modules.

Tests each module independently on one sample from the test set.
Requires: .env configured with DASHSCOPE_API_KEY + Chroma DB rebuilt.

Usage:
    python scripts/test_rag_modules.py
"""

import asyncio
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")


def load_one_sample():
    test_path = ROOT / "data" / "test_v2.jsonl"
    with open(test_path, "r", encoding="utf-8") as f:
        for line in f:
            sample = json.loads(line.strip())
            code = sample.get("vulnerable_code", "") or sample.get("code", "")
            if code and len(code) > 50:
                return sample
    return None


async def test_b1_bm25():
    """Test BM25 retriever standalone."""
    print("\n[B1] BM25 Retriever...")
    try:
        from rag.bm25_retriever import BM25Retriever
        bm25 = BM25Retriever()
        assert bm25.is_ready(), "BM25 index not ready"
        results = bm25.search("strcpy buffer overflow", k=3)
        assert len(results) > 0, "No results returned"
        print(f"    [PASS] {len(results)} results, top score={results[0].metadata.get('bm25_score', 0):.2f}")
        return True
    except Exception as e:
        print(f"    [FAIL] {e}")
        return False


async def test_b1_hybrid(sample_code):
    """Test Hybrid retriever (BM25 + Dense)."""
    print("\n[B1] Hybrid Retriever (BM25 + Dense)...")
    try:
        from rag import RAGRetriever, BM25Retriever, HybridRetriever
        dense = RAGRetriever(persist_dir=str(ROOT / "data" / "chroma_db"))
        bm25 = BM25Retriever()
        hybrid = HybridRetriever(dense_retriever=dense, bm25_retriever=bm25)
        results = await hybrid.retrieve(sample_code, k=5)
        assert len(results) > 0, "No results returned"
        has_rrf = any("rrf_score" in d.metadata for d in results)
        print(f"    [PASS] {len(results)} results, RRF scores present: {has_rrf}")
        return True
    except Exception as e:
        print(f"    [FAIL] {e}")
        return False


async def test_b2_metadata_filter(sample_code):
    """Test Dense retrieval with metadata filter."""
    print("\n[B2] Metadata Filter...")
    try:
        from rag import RAGRetriever
        retriever = RAGRetriever(persist_dir=str(ROOT / "data" / "chroma_db"))
        results_unfiltered = await retriever.retrieve(sample_code, k=5)
        results_filtered = await retriever.retrieve(sample_code, k=5, cwe_filter="CWE-476")
        print(f"    Unfiltered: {len(results_unfiltered)} results")
        print(f"    Filtered (CWE-476): {len(results_filtered)} results")
        if results_filtered:
            all_match = all(d.metadata.get("cwe_id") == "CWE-476" for d in results_filtered)
            print(f"    All match CWE-476: {all_match}")
        print(f"    [PASS]")
        return True
    except Exception as e:
        print(f"    [FAIL] {e}")
        return False


async def test_b3_hyde(sample_code):
    """Test HyDE query rewriting."""
    print("\n[B3] HyDE Query Rewriter...")
    try:
        from langchain_openai import ChatOpenAI
        from rag.hyde import HyDERewriter

        llm = ChatOpenAI(
            model=os.getenv("LLM_MODEL", "qwen-plus"),
            openai_api_key=os.getenv("DASHSCOPE_API_KEY"),
            openai_api_base=os.getenv("LLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
            temperature=0.1,
        )
        hyde = HyDERewriter(llm=llm)
        rewritten = await hyde.rewrite(sample_code[:500])
        assert len(rewritten) > 20, f"Rewritten too short: {len(rewritten)} chars"
        print(f"    Rewritten query ({len(rewritten)} chars): {rewritten[:100]}...")
        print(f"    [PASS]")
        return True
    except Exception as e:
        print(f"    [FAIL] {e}")
        return False


async def test_b4_reranker(sample_code):
    """Test Cross-Encoder reranker."""
    print("\n[B4] Cross-Encoder Reranker...")
    try:
        from rag.bm25_retriever import BM25Retriever
        from rag.reranker import CrossEncoderReranker

        bm25 = BM25Retriever()
        candidates = bm25.search(sample_code, k=10)
        if not candidates:
            print(f"    [SKIP] No candidates to rerank")
            return True

        reranker = CrossEncoderReranker()
        reranked = reranker.rerank(sample_code, candidates, top_k=3)
        assert len(reranked) > 0, "No results after reranking"
        has_score = "reranker_score" in reranked[0].metadata
        print(f"    Reranked {len(candidates)} -> {len(reranked)}, has score: {has_score}")
        print(f"    [PASS]")
        return True
    except Exception as e:
        print(f"    [FAIL] {e}")
        print(f"    (Cross-encoder model download may be needed, ~1GB)")
        return False


async def test_b5_crag(sample_code):
    """Test CRAG evaluator."""
    print("\n[B5] CRAG Quality Evaluator...")
    try:
        from langchain_openai import ChatOpenAI
        from rag.bm25_retriever import BM25Retriever
        from rag.corrective import CRAGEvaluator

        llm = ChatOpenAI(
            model=os.getenv("LLM_MODEL", "qwen-plus"),
            openai_api_key=os.getenv("DASHSCOPE_API_KEY"),
            openai_api_base=os.getenv("LLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
            temperature=0.1,
        )
        bm25 = BM25Retriever()
        docs = bm25.search(sample_code, k=5)
        evaluator = CRAGEvaluator(llm=llm)
        quality = await evaluator.evaluate(sample_code, docs)
        print(f"    Quality judgment: {quality.value}")
        print(f"    [PASS]")
        return True
    except Exception as e:
        print(f"    [FAIL] {e}")
        return False


async def main():
    print("=" * 60)
    print("RAG MODULE INTEGRATION TEST")
    print("=" * 60)

    sample = load_one_sample()
    if not sample:
        print("ERROR: Could not load test sample")
        return

    code = sample.get("vulnerable_code", "") or sample.get("code", "")
    print(f"\nTest sample: {sample.get('id', '?')}")
    print(f"CWE: {sample.get('cwe_id', '?')}, Language: {sample.get('language', '?')}")
    print(f"Code length: {len(code)} chars")

    results = {}
    results["B1-BM25"] = await test_b1_bm25()
    results["B1-Hybrid"] = await test_b1_hybrid(code)
    results["B2-Filter"] = await test_b2_metadata_filter(code)
    results["B3-HyDE"] = await test_b3_hyde(code)
    results["B4-Reranker"] = await test_b4_reranker(code)
    results["B5-CRAG"] = await test_b5_crag(code)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for name, passed in results.items():
        status = "[PASS]" if passed else "[FAIL]"
        print(f"  {status} {name}")

    passed_count = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"\n  {passed_count}/{total} modules passed")
    if passed_count < total:
        print("\n  NOTE: B3/B5 need DASHSCOPE_API_KEY in .env")
        print("  NOTE: B4 needs ~1GB model download (first run)")
        print("  NOTE: B2 needs Chroma rebuilt with metadata (run build_chroma_db.py --reset)")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
