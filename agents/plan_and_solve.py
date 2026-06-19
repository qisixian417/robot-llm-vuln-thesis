# [C8: Plan-and-Solve Agent] 三步分析：识别危险操作→追踪输入来源→检查防护措施，比单次LLM判断更准确（Recall=0.944）
"""Plan-and-Solve Agent for vulnerability detection.

Instead of one-shot LLM judgment, this agent:
1. Generates an analysis plan (what steps to take)
2. Executes each step with focused LLM calls
3. Synthesizes results into a final verdict

Each step is a small, focused LLM call:
  Step 1: Identify dangerous operations (strcpy, system, malloc, etc.)
  Step 2: Trace data flow (where does input come from?)
  Step 3: Check for defensive measures (null checks, bounds, sanitization)
  Step 4: Synthesize evidence → final verdict

Benefits over one-shot:
- Each step is focused → less hallucination
- Intermediate results can be inspected
- Uncertainty accumulates naturally (uncertain step → lower final confidence)

Reference: Plan-and-Solve (Wang et al., 2023)
"""

import json
from typing import Dict, Any, List, Optional

from langchain_core.language_models import BaseChatModel


PLAN_PROMPT = """你是一位安全分析师。为检测以下代码中的漏洞，制定一个3步分析计划。

代码：
```
{code}
```

只输出JSON：
{{
  "cwe_suspects": ["CWE-XXX", ...],  // 可能存在的CWE类型列表（最多3个）
  "dangerous_ops": ["op1", "op2"],   // 需要调查的危险操作
  "analysis_steps": [
    {{"step": 1, "task": "...", "focus": "..."}},
    {{"step": 2, "task": "...", "focus": "..."}},
    {{"step": 3, "task": "...", "focus": "..."}}
  ]
}}"""


STEP_PROMPT = """你正在分析代码中的漏洞：{step_task}

代码：
```
{code}
```

前几步的上下文：
{prior_context}

参考漏洞案例：
{rag_context}

重点关注：{step_focus}

只输出JSON：
{{
  "finding": "你发现了什么（1-2句话）",
  "evidence": "支持你发现的具体代码细节",
  "risk_level": "high（高）" | "medium（中）" | "low（低）" | "none（无）",
  "uncertainty": "你不确定的地方（1句话，或填'无'）"
}}"""


SYNTHESIS_PROMPT = """你正在综合漏洞分析步骤以做出最终判断。

代码：
```
{code}
```

分析计划与结果：
{step_results}

根据以上所有证据，做出最终的漏洞判断。

只输出JSON：
{{
  "has_vulnerability": true/false,
  "vulnerability_type": "CWE-XXX: 名称" 或 null,
  "reason": "证据综合（2-3句话）",
  "confidence": 0.0-1.0,
  "vulnerable_lines": [{{"line_number": N, "code": "...", "explanation": "..."}}]
}}

保守判断：只有当多个步骤发现一致的证据时，才标记为漏洞。"""


class PlanAndSolveAgent:
    """Multi-step vulnerability analysis via planning and execution."""

    def __init__(self, llm: BaseChatModel):
        self.llm = llm

    async def detect(
        self,
        code: str,
        rag_documents: Optional[List] = None,
        cwe_hint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run Plan-and-Solve vulnerability detection."""

        rag_context = self._format_rag(rag_documents or [])

        # Step 1: Generate analysis plan
        plan = await self._generate_plan(code, cwe_hint)
        if plan is None:
            plan = {
                "cwe_suspects": [cwe_hint or "未知"],
                "dangerous_ops": ["未知"],
                "analysis_steps": [
                    {"step": 1, "task": "识别危险操作", "focus": "不安全的函数调用"},
                    {"step": 2, "task": "追踪输入来源", "focus": "外部/用户输入流"},
                    {"step": 3, "task": "检查防护措施", "focus": "边界/空值检查"},
                ]
            }

        steps = plan.get("analysis_steps", [])[:3]
        step_results = []
        prior_context = "暂无前置步骤。"

        # Execute each step
        for step_info in steps:
            result = await self._execute_step(
                code=code,
                step_info=step_info,
                prior_context=prior_context,
                rag_context=rag_context,
            )
            step_results.append({
                "step": step_info.get("step"),
                "task": step_info.get("task"),
                "result": result,
            })
            # Update context for next step
            finding = result.get("finding", "")
            evidence = result.get("evidence", "")
            risk = result.get("risk_level", "unknown")
            prior_context = "\n".join(
                f"Step {r['step']} ({r['task']}): {r['result'].get('finding', '')} [risk={r['result'].get('risk_level', '?')}]"
                for r in step_results
            )

        # Step N+1: Synthesize
        verdict = await self._synthesize(code, step_results)

        # Attach plan metadata
        verdict["plan_steps"] = step_results
        verdict["cwe_suspects"] = plan.get("cwe_suspects", [])

        return verdict

    async def _generate_plan(self, code: str, cwe_hint: Optional[str]) -> Optional[Dict]:
        hint_text = f"\nSuspected CWE: {cwe_hint}" if cwe_hint and cwe_hint != "OTHER" else ""
        prompt = PLAN_PROMPT.format(code=code[:2000]) + hint_text
        try:
            response = await self.llm.ainvoke(prompt)
            return self._parse_json(response.content)
        except Exception:
            return None

    async def _execute_step(
        self,
        code: str,
        step_info: Dict,
        prior_context: str,
        rag_context: str,
    ) -> Dict[str, Any]:
        prompt = STEP_PROMPT.format(
            code=code[:2000],
            step_task=step_info.get("task", "Analyze code"),
            step_focus=step_info.get("focus", "general"),
            prior_context=prior_context[:500],
            rag_context=rag_context[:800],
        )
        try:
            response = await self.llm.ainvoke(prompt)
            result = self._parse_json(response.content)
            return result or {"finding": "Could not parse", "risk_level": "unknown"}
        except Exception as e:
            return {"finding": f"Error: {e}", "risk_level": "unknown"}

    async def _synthesize(self, code: str, step_results: List[Dict]) -> Dict[str, Any]:
        steps_text = "\n\n".join(
            f"Step {r['step']} — {r['task']}:\n"
            f"  Finding: {r['result'].get('finding', 'N/A')}\n"
            f"  Evidence: {r['result'].get('evidence', 'N/A')}\n"
            f"  Risk: {r['result'].get('risk_level', 'unknown')}\n"
            f"  Uncertainty: {r['result'].get('uncertainty', 'none')}"
            for r in step_results
        )
        prompt = SYNTHESIS_PROMPT.format(
            code=code[:2000],
            step_results=steps_text,
        )
        try:
            response = await self.llm.ainvoke(prompt)
            result = self._parse_json(response.content)
            if result:
                result.setdefault("has_vulnerability", False)
                result.setdefault("vulnerability_type", None)
                result.setdefault("reason", "")
                result.setdefault("confidence", 0.5)
                result.setdefault("vulnerable_lines", [])
                try:
                    result["confidence"] = max(0.0, min(1.0, float(result["confidence"])))
                except (TypeError, ValueError):
                    result["confidence"] = 0.5
                return result
        except Exception:
            pass
        return {
            "has_vulnerability": False,
            "vulnerability_type": None,
            "reason": "Synthesis failed",
            "confidence": 0.0,
            "vulnerable_lines": [],
        }

    def _parse_json(self, raw: str) -> Optional[Dict]:
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
                    return json.loads(text[start:end+1])
                except json.JSONDecodeError:
                    pass
        return None

    def _format_rag(self, docs: List) -> str:
        if not docs:
            return "No reference cases available."
        parts = []
        for i, doc in enumerate(docs[:3]):
            content = getattr(doc, "page_content", str(doc))
            meta = getattr(doc, "metadata", {})
            cwe = meta.get("cwe_id", "?")
            parts.append(f"Case {i+1} [{cwe}]: {content[:300]}")
        return "\n\n".join(parts)
