"""Orchestrator Agent - 协调其他Agent的工作流"""

from typing import Dict, Any, List
from langchain_core.messages import HumanMessage, AIMessage


class OrchestratorAgent:
    """协调Agent，负责任务分解和Agent调度"""

    def __init__(self, llm):
        self.llm = llm
        self.agents = {}

    def register_agent(self, name: str, agent):
        """注册子Agent"""
        self.agents[name] = agent

    async def process(self, code: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """处理代码检测流程"""
        results = {
            "code": code,
            "analysis": None,
            "vulnerabilities": [],
            "fixes": []
        }

        # 步骤1: 代码分析
        if "code_analyzer" in self.agents:
            results["analysis"] = await self.agents["code_analyzer"].analyze(code)

        # 步骤2: 漏洞检测
        if "vuln_detector" in self.agents:
            results["vulnerabilities"] = await self.agents["vuln_detector"].detect(
                code, results["analysis"]
            )

        # 步骤3: 生成修复建议
        if "fix_generator" in self.agents and results["vulnerabilities"]:
            results["fixes"] = await self.agents["fix_generator"].generate_fixes(
                code, results["vulnerabilities"]
            )

        return results
