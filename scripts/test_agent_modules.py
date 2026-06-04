# [集成测试] 测试C组Agent模块（Router/Detection/Verifier/Coordinator）是否正常工作
#!/usr/bin/env python3
"""Integration test for C-group Multi-Agent modules.

Tests Router, Detection (with CWE-specific prompts), Verifier (sandbox),
and the full LangGraph Coordinator pipeline.

Requires: .env with DASHSCOPE_API_KEY + Chroma DB built.

Usage:
    python scripts/test_agent_modules.py
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


def get_llm():
    from langchain_openai import ChatOpenAI
    return ChatOpenAI(
        model=os.getenv("LLM_MODEL", "qwen-plus"),
        openai_api_key=os.getenv("DASHSCOPE_API_KEY"),
        openai_api_base=os.getenv("LLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
        temperature=0.1,
    )


def load_test_samples(n=2):
    """Load 2 samples: 1 vulnerable + 1 clean."""
    test_path = ROOT / "data" / "test_v2.jsonl"
    vuln, clean = None, None
    with open(test_path, "r", encoding="utf-8") as f:
        for line in f:
            s = json.loads(line.strip())
            code = s.get("vulnerable_code", "") or s.get("code", "")
            if not code or len(code) < 80:
                continue
            if s.get("label") == 1 and vuln is None:
                vuln = s
            elif s.get("label") == 0 and clean is None:
                clean = s
            if vuln and clean:
                break
    return vuln, clean


async def test_c1_router(vuln_sample):
    """Test Router Agent CWE classification."""
    print("\n[C1] Router Agent...")
    try:
        from agents.router import RouterAgent
        router = RouterAgent(llm=get_llm())
        code = vuln_sample.get("vulnerable_code", "") or vuln_sample.get("code", "")
        result = await router.route(code)
        print(f"    Sample: {vuln_sample.get('id', '?')} (true CWE: {vuln_sample.get('cwe_id', '?')})")
        print(f"    Predicted: {result['primary']} (confidence={result['confidence']:.2f})")
        print(f"    Use filter: {result['use_filter']}")
        print(f"    [PASS]")
        return True
    except Exception as e:
        print(f"    [FAIL] {e}")
        import traceback; traceback.print_exc()
        return False


async def test_c2_detection(vuln_sample):
    """Test CWE-specific detection."""
    print("\n[C2] Detection Agent (CWE-specific prompt)...")
    try:
        from agents.vuln_detector import VulnDetectorAgent
        detector = VulnDetectorAgent(llm=get_llm())
        code = vuln_sample.get("vulnerable_code", "") or vuln_sample.get("code", "")
        result = await detector.detect(code, cwe_hint=vuln_sample.get("cwe_id"))
        print(f"    Has vulnerability: {result.get('has_vulnerability')}")
        print(f"    Type: {result.get('vulnerability_type')}")
        print(f"    Confidence: {result.get('confidence', 0):.2f}")
        print(f"    Reason (excerpt): {result.get('reason', '')[:100]}...")
        print(f"    [PASS]")
        return True
    except Exception as e:
        print(f"    [FAIL] {e}")
        import traceback; traceback.print_exc()
        return False


async def test_c3_verifier_minimal():
    """Test Verifier with a synthetic obvious-bug code (avoid waiting on real samples)."""
    print("\n[C3] Verification Agent (sandbox PoC)...")
    print("    Using synthetic CWE-119 example (strcpy overflow)...")
    try:
        from agents.verifier import VerificationAgent
        from agents.sandbox import _docker_available

        docker_ok = _docker_available()
        print(f"    Docker available: {docker_ok}")
        if not docker_ok:
            print(f"    (Will use local fallback - WARNING: less safe but functional)")

        synthetic_code = """
void process(const char* input) {
    char buf[64];
    strcpy(buf, input);
}
"""
        verifier = VerificationAgent(llm=get_llm(), max_retries=1)
        result = await verifier.verify(
            code=synthetic_code,
            cwe="CWE-119",
            reason="strcpy without length check on fixed buffer",
            language="C++",
        )
        print(f"    Verified: {result['verified']}")
        print(f"    Confidence: {result['confidence']:.2f}")
        print(f"    Evidence: {result['evidence'][:120]}")
        print(f"    Attempts: {result['attempts']}")
        print(f"    [PASS]")
        return True
    except Exception as e:
        print(f"    [FAIL] {e}")
        import traceback; traceback.print_exc()
        return False


async def test_c4_coordinator(vuln_sample):
    """Test full pipeline via LangGraph Coordinator."""
    print("\n[C4] Pipeline Coordinator (LangGraph end-to-end)...")
    try:
        from pipeline.coordinator import Coordinator
        coord = Coordinator(
            llm=get_llm(),
            chroma_persist_dir=str(ROOT / "data" / "chroma_db"),
            rag_corpus_path=str(ROOT / "data" / "rag_corpus_v2.jsonl"),
            enable_hyde=True,
            enable_hybrid=True,
            enable_reranker=True,
            enable_crag=True,
            enable_router=True,
            enable_verifier=False,
            use_local_reranker=False,
            retrieval_k=3,
        )
        code = vuln_sample.get("vulnerable_code", "") or vuln_sample.get("code", "")
        result = await coord.run(code, language=vuln_sample.get("language", "C++"))

        print(f"    Sample: {vuln_sample.get('id', '?')}")
        print(f"    Router: {result['router']['primary']} (conf={result['router']['confidence']:.2f})")
        print(f"    RAG quality: {result['rag_quality']}, docs={result['rag_doc_count']}")
        print(f"    Detection: {result['detection'].get('has_vulnerability')}, type={result['detection'].get('vulnerability_type')}")
        print(f"    Final verdict: {result['verdict']['label']} (conf={result['verdict']['confidence']:.2f})")
        print(f"    [PASS]")
        return True
    except Exception as e:
        print(f"    [FAIL] {e}")
        import traceback; traceback.print_exc()
        return False


async def main():
    print("=" * 60)
    print("AGENT MODULE INTEGRATION TEST (C-group)")
    print("=" * 60)

    vuln, clean = load_test_samples()
    if not vuln:
        print("ERROR: Could not load vulnerable test sample")
        return

    print(f"\nVulnerable sample: {vuln.get('id', '?')} (CWE={vuln.get('cwe_id', '?')})")

    results = {}
    results["C1-Router"] = await test_c1_router(vuln)
    results["C2-Detection"] = await test_c2_detection(vuln)
    results["C3-Verifier"] = await test_c3_verifier_minimal()
    results["C4-Coordinator"] = await test_c4_coordinator(vuln)

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
        print("\n  COMMON ISSUES:")
        print("  - C1/C2/C4: needs DASHSCOPE_API_KEY in .env")
        print("  - C3: needs g++ compiler (Docker preferred, local fallback OK)")
        print("  - C4: needs Chroma DB built (run build_chroma_db.py)")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
