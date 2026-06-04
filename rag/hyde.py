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
    ("system", """You are a vulnerability documentation expert.
Given a code snippet, write a brief hypothetical vulnerability description
that would appear in a security advisory if this code contained a vulnerability.

Focus on:
- What type of vulnerability could exist (CWE category)
- What unsafe patterns are present
- What the impact would be

Write 2-3 sentences in English. Be specific about the code patterns you observe.
If the code appears safe, describe what vulnerability it COULD have had and why it doesn't.

Output ONLY the description, nothing else."""),
    ("user", "Code:\n```\n{code}\n```"),
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
