"""Code Analyzer Agent - 分析代码结构和语义"""

from typing import Dict, Any
from langchain_core.prompts import ChatPromptTemplate


class CodeAnalyzerAgent:
    """代码分析Agent"""

    def __init__(self, llm):
        self.llm = llm
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """你是一个机器人代码分析专家。分析给定的代码并提取关键信息：
1. 代码类型（ROS节点/驱动/控制器等）
2. 主要功能
3. 关键API调用
4. 潜在风险点

以JSON格式返回分析结果。"""),
            ("user", "请分析以下代码：\n\n{code}")
        ])

    async def analyze(self, code: str) -> Dict[str, Any]:
        """分析代码"""
        chain = self.prompt | self.llm
        response = await chain.ainvoke({"code": code})

        return {
            "summary": response.content,
            "code_type": "unknown",
            "key_apis": [],
            "risk_areas": []
        }
