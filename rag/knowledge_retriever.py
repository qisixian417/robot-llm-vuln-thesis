# [KL-RAG: 知识级检索] 核心RAG模块：查询侧用LLM提炼知识描述，匹配知识库的根因+触发+修复文字，优于代码字面匹配
"""Knowledge-Level RAG Retriever.

Inspired by Vul-RAG (Du et al., 2024). Instead of retrieving similar code,
this retriever retrieves similar VULNERABILITY KNOWLEDGE — abstract semantic
descriptions of the vulnerability rather than the literal code.

Pipeline:
1. At index time: each historical vulnerability is decomposed into
   (functional_semantics, root_cause, trigger_condition, fix_pattern)
   The combined knowledge text is embedded.
2. At query time: the query code is first decomposed into the same 4 fields
   via LLM. The query knowledge text is embedded and matched against the index.

This decouples retrieval from lexical code similarity, allowing the system
to find cases that share vulnerability SEMANTICS even with very different code.
"""

import json
import os
from pathlib import Path
from typing import List, Optional

from langchain_community.vectorstores import Chroma
from langchain_core.documents import Document
from langchain_core.language_models import BaseChatModel
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import OpenAIEmbeddings


DEFAULT_KL_PERSIST_DIR = "./data/chroma_kl_db"
DEFAULT_KL_COLLECTION_NAME = "roboguard_kl_rag"


# Same 4-field schema as build_knowledge_base.py
QUERY_KNOWLEDGE_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """你是一位资深安全分析师。分析给定的代码片段，提取结构化知识用于识别潜在漏洞。

沿4个维度提取知识：
1. functional_semantics（功能语义）：代码应该做什么（1句话）
2. root_cause（根因）：什么可能出错/存在什么不安全模式（2句话以内）
3. trigger_condition（触发条件）：什么输入或状态会触发问题（1句话）
4. fix_pattern（修复模式）：如何修复（1-2句话）

如果代码看起来安全，描述缺少哪种不安全模式以及为什么安全。

严格输出JSON，不要markdown代码块：
{{
  "functional_semantics": "...",
  "root_cause": "...",
  "trigger_condition": "...",
  "fix_pattern": "..."
}}"""),
    ("user", "代码：\n```\n{code}\n```"),
])


def _format_knowledge(item: dict) -> str:
    """Combine knowledge fields into a single embeddable text."""
    return (
        f"功能语义：{item.get('functional_semantics', '')}\n\n"
        f"漏洞根因：{item.get('root_cause', '')}\n\n"
        f"触发条件：{item.get('trigger_condition', '')}\n\n"
        f"修复模式：{item.get('fix_pattern', '')}"
    )


def _parse_query_knowledge(raw: str) -> dict:
    text = raw.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1] if lines[-1].startswith("```") else lines[1:])
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if 0 <= start < end:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                pass
    return {
        "functional_semantics": "Unable to extract",
        "root_cause": "Unable to extract",
        "trigger_condition": "Unable to extract",
        "fix_pattern": "Unable to extract",
    }


class KnowledgeRAGRetriever:
    """Retrieves historical vulnerability cases via abstract knowledge similarity."""

    def __init__(
        self,
        llm: BaseChatModel,
        persist_dir: str = DEFAULT_KL_PERSIST_DIR,
        collection_name: Optional[str] = None,
    ):
        self.llm = llm
        self.persist_dir = persist_dir
        self.collection_name = collection_name or os.getenv(
            "CHROMA_KL_COLLECTION_NAME", DEFAULT_KL_COLLECTION_NAME
        )
        self.embeddings = OpenAIEmbeddings(
            model=os.getenv("EMBEDDING_MODEL", "text-embedding-v2"),
            openai_api_key=os.getenv("DASHSCOPE_API_KEY"),
            openai_api_base=os.getenv(
                "EMBEDDING_BASE_URL",
                "https://dashscope.aliyuncs.com/compatible-mode/v1",
            ),
            check_embedding_ctx_length=False,
            chunk_size=10,  # text-embedding-v3 max batch = 10
        )
        self.vectorstore = Chroma(
            collection_name=self.collection_name,
            persist_directory=self.persist_dir,
            embedding_function=self.embeddings,
        )
        self._extract_chain = QUERY_KNOWLEDGE_PROMPT | self.llm

    def count(self) -> int:
        return self.vectorstore._collection.count()

    def is_ready(self) -> bool:
        return self.count() > 0

    async def extract_query_knowledge(self, code: str) -> dict:
        """Use LLM to extract knowledge from query code."""
        response = await self._extract_chain.ainvoke({"code": code[:2500]})
        return _parse_query_knowledge(response.content)

    async def retrieve(
        self,
        query: str,
        k: int = 3,
        cwe_filter: Optional[str] = None,
        language_filter: Optional[str] = None,
        return_query_knowledge: bool = False,
    ):
        """Retrieve historical vulnerability cases via knowledge similarity.

        Args:
            query: query CODE (will be converted to knowledge internally)
            k: number of results
            cwe_filter / language_filter: metadata filters
            return_query_knowledge: if True, return (docs, query_knowledge_dict)
        """
        query_knowledge = await self.extract_query_knowledge(query)
        query_text = _format_knowledge(query_knowledge)

        where_filter = {}
        if cwe_filter:
            where_filter["cwe_id"] = cwe_filter
        if language_filter:
            where_filter["language"] = language_filter

        if where_filter:
            docs = self.vectorstore.similarity_search(query_text, k=k, filter=where_filter)
        else:
            docs = self.vectorstore.similarity_search(query_text, k=k)

        if return_query_knowledge:
            return docs, query_knowledge
        return docs

    def add_documents(self, documents: List[Document]) -> None:
        self.vectorstore.add_documents(documents)
        persist = getattr(self.vectorstore, "persist", None)
        if callable(persist):
            try:
                persist()
            except Exception:
                pass

    def reset(self) -> None:
        self.vectorstore.delete_collection()
        self.vectorstore = Chroma(
            collection_name=self.collection_name,
            persist_directory=self.persist_dir,
            embedding_function=self.embeddings,
        )


def knowledge_to_documents(items: List[dict]) -> List[Document]:
    """Convert knowledge JSONL items to LangChain Documents.

    page_content = formatted knowledge text (for embedding)
    metadata = original fields + raw_code (for inspection)
    """
    documents = []
    for item in items:
        content = _format_knowledge(item)
        metadata = {
            "id": item.get("id"),
            "cwe_id": item.get("cwe_id"),
            "language": item.get("language"),
            "repo": item.get("repo"),
            "ros_component": item.get("ros_component"),
            "ros_version": item.get("ros_version"),
            "functional_semantics": item.get("functional_semantics", "")[:500],
            "root_cause": item.get("root_cause", "")[:500],
            "trigger_condition": item.get("trigger_condition", "")[:500],
            "fix_pattern": item.get("fix_pattern", "")[:500],
            "raw_code": item.get("raw_code", "")[:1000],
        }
        metadata = {k: v for k, v in metadata.items() if v}
        documents.append(Document(page_content=content, metadata=metadata))
    return documents
