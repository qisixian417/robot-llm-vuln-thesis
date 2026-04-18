"""Vulnerability Detector Agent - 检测代码漏洞"""

from typing import Dict, Any, List
from langchain_core.prompts import ChatPromptTemplate


class VulnDetectorAgent:
    """漏洞检测Agent"""

    def __init__(self, llm, rag_retriever=None):
        self.llm = llm
        self.rag_retriever = rag_retriever
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """你是机器人代码安全专家。检测代码中的安全漏洞。

参考知识：
{context}

重点关注：
- 缓冲区溢出
- 空指针解引用
- 资源泄漏
- 并发问题
- ROS特定漏洞

返回JSON格式的漏洞列表。"""),
            ("user", "代码分析：{analysis}\n\n代码：\n{code}")
        ])

    async def detect(self, code: str, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """检测漏洞"""
        context = ""
        if self.rag_retriever:
            docs = await self.rag_retriever.retrieve(code)
            context = "\n".join([doc.page_content for doc in docs])

        chain = self.prompt | self.llm
        response = await chain.ainvoke({
            "code": code,
            "analysis": str(analysis),
            "context": context
        })

        return [{"type": "unknown", "description": response.content}]
