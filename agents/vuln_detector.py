"""Vulnerability Detector Agent - 检测代码漏洞"""

import json
from typing import Dict, Any, List
from langchain_core.prompts import ChatPromptTemplate


class VulnDetectorAgent:
    """漏洞检测Agent"""

    def __init__(self, llm, rag_retriever=None):
        self.llm = llm
        self.rag_retriever = rag_retriever
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """你是机器人代码安全专家。检测代码中的安全漏洞。

参考知识（从历史漏洞案例中检索）：
{context}

输入的代码每行都有行号前缀（格式：L1: 代码内容）。请分析代码并返回JSON格式的检测结果。

如果发现漏洞，返回：
{{
  "has_vulnerability": true,
  "vulnerability_type": "CWE-XXX: 漏洞类型名称",
  "reason": "详细说明为什么存在这个漏洞",
  "confidence": 0.0-1.0,
  "vulnerable_lines": [
    {{"line_number": 行号, "code": "该行代码内容", "explanation": "该行为什么有问题"}}
  ]
}}

如果没有发现漏洞，返回：
{{
  "has_vulnerability": false,
  "vulnerability_type": null,
  "reason": "代码看起来是安全的",
  "confidence": 0.8,
  "vulnerable_lines": []
}}

重点关注：
- 缓冲区溢出 (CWE-119)
- 空指针解引用 (CWE-476)
- 资源泄漏 (CWE-401)
- 并发问题 (CWE-362)
- 命令注入 (CWE-78)
- Use After Free (CWE-416)
- 整数溢出 (CWE-190)
- 格式化字符串 (CWE-134)
- ROS特定漏洞

只返回JSON，不要其他文字。"""),
            ("user", "代码：\n{code}")
        ])

    async def detect(self, code: str) -> Dict[str, Any]:
        """检测漏洞"""
        # 检索相关知识
        rag_docs = []
        context = "无相关历史案例"

        if self.rag_retriever:
            docs = await self.rag_retriever.retrieve(code)
            rag_docs = [
                {
                    "content": doc.page_content,
                    "metadata": doc.metadata
                }
                for doc in docs
            ]
            if docs:
                context = "\n\n".join([
                    f"案例{i+1}: {doc.page_content}\n元数据: {doc.metadata}"
                    for i, doc in enumerate(docs)
                ])

        # 给代码添加行号
        numbered_code = "\n".join(
            f"L{i+1}: {line}" for i, line in enumerate(code.splitlines())
        )

        # 调用LLM检测
        chain = self.prompt | self.llm
        response = await chain.ainvoke({
            "code": numbered_code,
            "context": context
        })

        # 解析LLM返回的JSON
        try:
            result = json.loads(response.content)
        except json.JSONDecodeError:
            result = {
                "has_vulnerability": False,
                "vulnerability_type": None,
                "reason": "无法解析检测结果",
                "confidence": 0.0,
                "vulnerable_lines": []
            }

        # 确保 vulnerable_lines 字段存在
        if "vulnerable_lines" not in result:
            result["vulnerable_lines"] = []

        # 添加RAG检索结果
        result["retrieved_knowledge"] = rag_docs

        return result
