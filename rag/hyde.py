# [B3: HyDE查询改写] 用LLM将代码改写为假设性漏洞描述再检索（实验显示在本数据集有害-2%F1，作为负向发现保留）
"""HyDE (Hypothetical Document Embeddings) query rewriter.

Bridges the semantic gap between raw code queries and vulnerability descriptions
stored in the RAG corpus. The LLM generates a hypothetical vulnerability
description, which is then used as the retrieval query.

Reference: Gao et al., "Precise Zero-Shot Dense Retrieval without Relevance Labels", ACL 2023
"""

from langchain_core.language_models import BaseChatModel
from langchain_core.prompts import ChatPromptTemplate

HYDE_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """你是一位漏洞文档专家。
给定一段代码，写一段简短的假设性漏洞描述，就好像这段代码真的含有漏洞时安全公告里会出现的内容。

重点关注：
- 可能存在什么类型的漏洞（CWE分类）
- 存在哪些不安全的代码模式
- 影响会是什么

用2-3句话描述，要针对你观察到的具体代码模式。
如果代码看起来安全，描述它本来可能有什么漏洞以及为什么没有。

只输出描述内容，不要其他任何内容。"""),
    ("user", "代码：\n```\n{code}\n```"),
])


class HyDERewriter:
    """Generates a hypothetical vulnerability description to use as retrieval query."""

    def __init__(self, llm: BaseChatModel):
        self.llm = llm
        self.chain = HYDE_PROMPT | self.llm

    async def rewrite(self, code: str) -> str:
        """Generate hypothetical vulnerability description for the given code."""
        response = await self.chain.ainvoke({"code": code[:3000]})
        return response.content.strip()
