# [Naive Dense检索] 基础向量检索器：DashScope text-embedding-v3 + Chroma，支持cwe_id/language/component metadata过滤
"""RAG检索器 - 从Chroma向量数据库检索相关漏洞知识。"""

import os
from typing import List

from langchain_community.vectorstores import Chroma
from langchain_core.documents import Document
from langchain_openai import OpenAIEmbeddings


DEFAULT_PERSIST_DIR = "./data/chroma_db"
DEFAULT_COLLECTION_NAME = "roboguard_rag"


class RAGRetriever:
    """RAG检索系统。"""

    def __init__(
        self,
        persist_dir: str = DEFAULT_PERSIST_DIR,
        collection_name: str | None = None,
    ):
        self.persist_dir = persist_dir
        self.collection_name = (
            collection_name
            or os.getenv("CHROMA_COLLECTION_NAME", DEFAULT_COLLECTION_NAME)
        )
        self.embeddings = OpenAIEmbeddings(
            model=os.getenv("EMBEDDING_MODEL", "text-embedding-v2"),
            openai_api_key=os.getenv("DASHSCOPE_API_KEY"),
            openai_api_base=os.getenv(
                "EMBEDDING_BASE_URL",
                "https://dashscope.aliyuncs.com/compatible-mode/v1",
            ),
            # DashScope 的 embedding 兼容接口期望收到字符串，
            # 关闭 LangChain 的长度安全分词逻辑，避免传入 token 列表后报 400。
            check_embedding_ctx_length=False,
            # text-embedding-v3 supports max 10 items per batch
            chunk_size=10,
        )
        self.vectorstore = Chroma(
            collection_name=self.collection_name,
            persist_directory=self.persist_dir,
            embedding_function=self.embeddings,
        )

    async def retrieve(
        self,
        query: str,
        k: int = 3,
        cwe_filter: str | None = None,
        language_filter: str | None = None,
        component_filter: str | None = None,
    ) -> List[Document]:
        """检索相关文档,支持 metadata 过滤。"""
        where_filter = {}
        if cwe_filter:
            where_filter["cwe_id"] = cwe_filter
        if language_filter:
            where_filter["language"] = language_filter
        if component_filter:
            where_filter["ros_component"] = component_filter

        if where_filter:
            return self.vectorstore.similarity_search(
                query, k=k, filter=where_filter
            )
        return self.vectorstore.similarity_search(query, k=k)

    def add_documents(self, documents: List[Document]) -> None:
        """添加文档到知识库。"""
        self.vectorstore.add_documents(documents)
        self._persist()

    def reset(self) -> None:
        """清空当前集合，便于重新建库。"""
        self.vectorstore.delete_collection()
        self.vectorstore = Chroma(
            collection_name=self.collection_name,
            persist_directory=self.persist_dir,
            embedding_function=self.embeddings,
        )

    def count(self) -> int:
        """返回当前集合中的文档数量。"""
        return self.vectorstore._collection.count()

    def is_ready(self) -> bool:
        """判断当前向量数据库是否已有可检索文档。"""
        return self.count() > 0

    def _persist(self) -> None:
        """兼容不同 Chroma 版本的持久化行为。"""
        persist = getattr(self.vectorstore, "persist", None)
        if callable(persist):
            persist()
