# [C4: Pipeline Coordinator] LangGraph状态机：串联Router→RAG检索→Detection→可选(Verifier/Voting/Debate/Reflection/PlanAndSolve/AST)的完整检测流水线
"""Pipeline Coordinator - LangGraph state machine orchestrating all agents.

State flow:
    [Router] -> [RAG Retrieval] -> [Detection] -> [Verification?] -> [End]

Branching logic:
- After Detection: if has_vulnerability AND verifier_enabled -> Verification
- After Detection: if no vulnerability -> End (skip verification)
"""

from typing import Any, Dict, List, Optional, TypedDict

from langgraph.graph import END, StateGraph

from agents.router import RouterAgent
from agents.vuln_detector import VulnDetectorAgent
from agents.verifier import VerificationAgent
from agents.subagents import VotingSubagents, DebateSubagents
from agents.reflection import ReflectionAgent
from agents.plan_and_solve import PlanAndSolveAgent
from agents.ast_tool import ASTAugmentedDetector
from rag.bm25_retriever import BM25Retriever
from rag.corrective import CRAGEvaluator, CRAGPipeline
from rag.hybrid_retriever import HybridRetriever
from rag.hyde import HyDERewriter
from rag.knowledge_retriever import KnowledgeRAGRetriever
from rag.reranker import CrossEncoderReranker, LLMReranker
from rag.retriever import RAGRetriever


class PipelineState(TypedDict, total=False):
    """State passed between pipeline nodes."""
    code: str
    language: str
    router_output: Dict[str, Any]
    rag_query: str
    rag_documents: List
    rag_quality: str
    detection_output: Dict[str, Any]
    verification_output: Optional[Dict[str, Any]]
    final_verdict: Dict[str, Any]
    config: Dict[str, Any]


class Coordinator:
    """Orchestrates the full multi-agent vulnerability detection pipeline."""

    def __init__(
        self,
        llm,
        chroma_persist_dir: str = "./data/chroma_db",
        kl_chroma_persist_dir: str = "./data/chroma_kl_db",
        rag_corpus_path: Optional[str] = None,
        enable_hyde: bool = True,
        enable_hybrid: bool = True,
        enable_reranker: bool = True,
        enable_crag: bool = True,
        enable_router: bool = True,
        enable_verifier: bool = False,
        enable_voting: bool = False,
        enable_debate: bool = False,
        enable_kl_rag: bool = False,
        enable_reflection: bool = False,
        enable_plan_and_solve: bool = False,
        enable_ast_tool: bool = False,
        use_local_reranker: bool = False,
        retrieval_k: int = 5,
    ):
        self.llm = llm
        self.config = {
            "enable_hyde": enable_hyde,
            "enable_hybrid": enable_hybrid,
            "enable_reranker": enable_reranker,
            "enable_crag": enable_crag,
            "enable_router": enable_router,
            "enable_verifier": enable_verifier,
            "enable_voting": enable_voting,
            "enable_debate": enable_debate,
            "enable_kl_rag": enable_kl_rag,
            "enable_reflection": enable_reflection,
            "enable_plan_and_solve": enable_plan_and_solve,
            "enable_ast_tool": enable_ast_tool,
            "retrieval_k": retrieval_k,
            "dense_k": 20,
            "bm25_k": 20,
            "rrf_top_k": 15,
            "reranker_top_k": 5,
        }

        self.dense_retriever = RAGRetriever(persist_dir=chroma_persist_dir)
        self.bm25_retriever = BM25Retriever(corpus_path=rag_corpus_path) if enable_hybrid else None
        self.hybrid_retriever = (
            HybridRetriever(self.dense_retriever, self.bm25_retriever)
            if enable_hybrid and self.bm25_retriever
            else None
        )
        self.kl_retriever = (
            KnowledgeRAGRetriever(llm=llm, persist_dir=kl_chroma_persist_dir)
            if enable_kl_rag
            else None
        )
        self.hyde = HyDERewriter(llm=llm) if (enable_hyde and not enable_kl_rag) else None
        self.reranker = (
            CrossEncoderReranker() if (enable_reranker and use_local_reranker)
            else (LLMReranker(llm=llm) if enable_reranker else None)
        )
        self.crag_pipeline = (
            CRAGPipeline(CRAGEvaluator(llm=llm)) if enable_crag else None
        )
        self.router = RouterAgent(llm=llm) if enable_router else None
        self.detector = VulnDetectorAgent(llm=llm)
        self.verifier = VerificationAgent(llm=llm) if enable_verifier else None
        self.voting_subagents = VotingSubagents(llm=llm) if enable_voting else None
        self.debate_subagents = DebateSubagents(llm=llm) if enable_debate else None
        self.reflection_agent = ReflectionAgent(llm=llm) if enable_reflection else None
        self.plan_solve_agent = PlanAndSolveAgent(llm=llm) if enable_plan_and_solve else None
        self.ast_detector = ASTAugmentedDetector(llm=llm) if enable_ast_tool else None

        self.graph = self._build_graph()

    def _build_graph(self):
        graph = StateGraph(PipelineState)

        graph.add_node("router", self._router_node)
        graph.add_node("retrieve", self._retrieve_node)
        graph.add_node("detect", self._detect_node)
        graph.add_node("verify", self._verify_node)
        graph.add_node("finalize", self._finalize_node)

        graph.set_entry_point("router")
        graph.add_edge("router", "retrieve")
        graph.add_edge("retrieve", "detect")

        graph.add_conditional_edges(
            "detect",
            self._should_verify,
            {"verify": "verify", "finalize": "finalize"},
        )
        graph.add_edge("verify", "finalize")
        graph.add_edge("finalize", END)

        return graph.compile()

    @staticmethod
    def _rrf_fuse(kl_docs, dense_docs, k: int, kl_weight: float = 0.7, dense_weight: float = 0.3):
        """Weighted RRF fusion of KL-RAG and Dense retrieval results."""
        from langchain_core.documents import Document
        rrf_k = 60
        scores: dict = {}
        doc_map: dict = {}

        def doc_key(doc):
            did = doc.metadata.get("id")
            return str(did) if did else str(hash(doc.page_content[:200]))

        for rank, doc in enumerate(kl_docs):
            key = doc_key(doc)
            scores[key] = scores.get(key, 0) + kl_weight / (rrf_k + rank + 1)
            doc.metadata["source_kl"] = True
            doc_map[key] = doc

        for rank, doc in enumerate(dense_docs):
            key = doc_key(doc)
            scores[key] = scores.get(key, 0) + dense_weight / (rrf_k + rank + 1)
            if key in doc_map:
                doc_map[key].metadata["source_dense"] = True
            else:
                doc.metadata["source_dense"] = True
                doc_map[key] = doc

        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        results = []
        for key, score in ranked[:k]:
            doc = doc_map[key]
            doc.metadata["rrf_score"] = round(score, 6)
            results.append(doc)
        return results

    async def _router_node(self, state: PipelineState) -> PipelineState:
        if self.router and self.config["enable_router"]:
            output = await self.router.route(state["code"])
        else:
            output = {"primary": "OTHER", "secondary": None, "confidence": 0.0, "use_filter": False}
        state["router_output"] = output
        return state

    async def _retrieve_node(self, state: PipelineState) -> PipelineState:
        code = state["code"]
        cwe_hint = state["router_output"]["primary"] if state["router_output"]["use_filter"] else None

        # KL-RAG: dual-path retrieval (KL knowledge + Dense code), fused via RRF + Reranker
        if self.kl_retriever and self.config["enable_kl_rag"]:
            dense_k = self.config.get("dense_k", 20)
            bm25_k = self.config.get("bm25_k", 20)
            rrf_top_k = self.config.get("rrf_top_k", 15)
            reranker_top_k = self.config.get("reranker_top_k", 5)
            kl_docs, dense_docs = [], []

            try:
                kl_docs = await self.kl_retriever.retrieve(
                    code, k=dense_k, cwe_filter=cwe_hint,
                )
            except Exception as e:
                print(f"[KL-RAG] retrieve failed: {e}")

            try:
                dense_docs = await self.dense_retriever.retrieve(code, k=bm25_k)
            except Exception as e:
                print(f"[Dense] retrieve failed: {e}")

            if kl_docs and dense_docs:
                docs = self._rrf_fuse(kl_docs, dense_docs, k=rrf_top_k, kl_weight=0.7, dense_weight=0.3)
                state["rag_query"] = "dual-path KL+Dense (RRF)"
            elif kl_docs:
                docs = kl_docs[:rrf_top_k]
                state["rag_query"] = "knowledge-level (LLM-extracted)"
            else:
                docs = dense_docs[:rrf_top_k]
                state["rag_query"] = "dense fallback"

            # Reranker: 从 rrf_top_k 条中精排出 reranker_top_k 条
            if self.reranker and self.config["enable_reranker"] and docs:
                if isinstance(self.reranker, LLMReranker):
                    docs = await self.reranker.rerank(code, docs, top_k=reranker_top_k)
                else:
                    docs = self.reranker.rerank(code, docs, top_k=reranker_top_k)
            else:
                docs = docs[:reranker_top_k]

            state["rag_quality"] = "N/A"
            state["rag_documents"] = docs
            return state

        query = code
        if self.hyde and self.config["enable_hyde"]:
            try:
                query = await self.hyde.rewrite(code)
            except Exception:
                query = code
        state["rag_query"] = query

        docs = []
        if self.crag_pipeline and self.config["enable_crag"]:
            retriever_for_crag = self.hybrid_retriever or self.dense_retriever
            crag_result = await self.crag_pipeline.retrieve_with_correction(
                query_code=query,
                retriever=retriever_for_crag,
                k=self.config["retrieval_k"] * 2,
                cwe_filter=cwe_hint,
            )
            docs = crag_result["documents"]
            state["rag_quality"] = crag_result["quality"].value
        elif self.hybrid_retriever and self.config["enable_hybrid"]:
            docs = await self.hybrid_retriever.retrieve(
                query, k=self.config["retrieval_k"] * 2, cwe_filter=cwe_hint,
            )
            state["rag_quality"] = "N/A"
        else:
            try:
                docs = await self.dense_retriever.retrieve(
                    query, k=self.config["retrieval_k"] * 2, cwe_filter=cwe_hint,
                )
            except TypeError:
                docs = await self.dense_retriever.retrieve(query, k=self.config["retrieval_k"] * 2)
            state["rag_quality"] = "N/A"

        if self.reranker and self.config["enable_reranker"] and docs:
            if isinstance(self.reranker, LLMReranker):
                docs = await self.reranker.rerank(code, docs, top_k=self.config["retrieval_k"])
            else:
                docs = self.reranker.rerank(code, docs, top_k=self.config["retrieval_k"])
        else:
            docs = docs[: self.config["retrieval_k"]]

        state["rag_documents"] = docs
        return state

    async def _detect_node(self, state: PipelineState) -> PipelineState:
        cwe_hint = state["router_output"]["primary"] if self.config["enable_router"] else None

        if self.plan_solve_agent and self.config["enable_plan_and_solve"]:
            output = await self.plan_solve_agent.detect(
                code=state["code"],
                rag_documents=state["rag_documents"],
                cwe_hint=cwe_hint,
            )
        elif self.ast_detector and self.config["enable_ast_tool"]:
            output = await self.ast_detector.detect(
                code=state["code"],
                cwe_hint=cwe_hint,
                rag_documents=state["rag_documents"],
            )
        elif self.debate_subagents and self.config["enable_debate"]:
            output = await self.debate_subagents.judge(
                code=state["code"],
                cwe_hint=cwe_hint,
                rag_documents=state["rag_documents"],
            )
        elif self.voting_subagents and self.config["enable_voting"]:
            output = await self.voting_subagents.judge(
                code=state["code"],
                cwe_hint=cwe_hint,
                rag_documents=state["rag_documents"],
            )
        else:
            output = await self.detector.detect(
                code=state["code"],
                cwe_hint=cwe_hint,
                rag_documents=state["rag_documents"],
            )

        # Apply Reflection if enabled
        if self.reflection_agent and self.config["enable_reflection"]:
            output = await self.reflection_agent.reflect(
                code=state["code"],
                detection_output=output,
            )

        state["detection_output"] = output
        return state

    def _should_verify(self, state: PipelineState) -> str:
        if not (self.verifier and self.config["enable_verifier"]):
            return "finalize"
        if state["detection_output"].get("has_vulnerability"):
            return "verify"
        return "finalize"

    async def _verify_node(self, state: PipelineState) -> PipelineState:
        det = state["detection_output"]
        cwe = det.get("vulnerability_type", "OTHER") or "OTHER"
        if ":" in cwe:
            cwe = cwe.split(":")[0].strip()
        output = await self.verifier.verify(
            code=state["code"],
            cwe=cwe,
            reason=det.get("reason", ""),
            language=state.get("language", "C++"),
        )
        state["verification_output"] = output
        return state

    async def _finalize_node(self, state: PipelineState) -> PipelineState:
        det = state["detection_output"]
        ver = state.get("verification_output")

        final_confidence = det.get("confidence", 0.5)
        verdict_label = "vulnerable" if det.get("has_vulnerability") else "clean"

        if ver:
            if ver["verified"] == "confirmed":
                final_confidence = max(final_confidence, ver["confidence"])
                verdict_label = "vulnerable_verified"
            elif ver["verified"] == "not_reproduced":
                final_confidence *= 0.5
                verdict_label = "vulnerable_unverified"
            elif ver["verified"] == "unverifiable":
                verdict_label = "vulnerable_unverifiable"

        state["final_verdict"] = {
            "label": verdict_label,
            "has_vulnerability": det.get("has_vulnerability", False),
            "vulnerability_type": det.get("vulnerability_type"),
            "confidence": final_confidence,
            "reason": det.get("reason", ""),
            "router_cwe": state["router_output"]["primary"],
            "rag_quality": state.get("rag_quality", "N/A"),
            "verification_status": ver["verified"] if ver else "not_run",
        }
        return state

    async def run(self, code: str, language: str = "C++") -> Dict[str, Any]:
        initial_state: PipelineState = {
            "code": code,
            "language": language,
            "config": self.config,
        }
        final_state = await self.graph.ainvoke(initial_state)
        return {
            "verdict": final_state["final_verdict"],
            "router": final_state["router_output"],
            "detection": final_state["detection_output"],
            "verification": final_state.get("verification_output"),
            "rag_quality": final_state.get("rag_quality"),
            "rag_doc_count": len(final_state.get("rag_documents", [])),
        }
