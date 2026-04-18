"""Fix Generator Agent - 生成修复建议"""

from typing import Dict, Any, List
from langchain_core.prompts import ChatPromptTemplate


class FixGeneratorAgent:
    """修复建议生成Agent"""

    def __init__(self, llm):
        self.llm = llm
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """你是代码修复专家。为检测到的漏洞生成修复建议。

要求：
1. 给出具体的修复代码
2. 解释修复原理
3. 考虑性能影响"""),
            ("user", "原始代码：\n{code}\n\n漏洞：\n{vulnerabilities}")
        ])

    async def generate_fixes(self, code: str, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """生成修复建议"""
        chain = self.prompt | self.llm
        response = await chain.ainvoke({
            "code": code,
            "vulnerabilities": str(vulnerabilities)
        })

        return [{"fix": response.content}]
