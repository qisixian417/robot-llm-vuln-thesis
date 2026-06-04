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


PLAN_PROMPT = """You are a security analyst. Create a 3-step analysis plan for detecting vulnerabilities in the given code.

Code:
```
{code}
```

Output JSON only:
{{
  "cwe_suspects": ["CWE-XXX", ...],  // list of CWE types that MIGHT be present (max 3)
  "dangerous_ops": ["op1", "op2"],   // dangerous operations to investigate
  "analysis_steps": [
    {{"step": 1, "task": "...", "focus": "..."}},
    {{"step": 2, "task": "...", "focus": "..."}},
    {{"step": 3, "task": "...", "focus": "..."}}
  ]
}}"""


STEP_PROMPT = """You are analyzing code for the vulnerability: {step_task}

Code:
```
{code}
```

Context from previous steps:
{prior_context}

Reference vulnerability cases:
{rag_context}

Focus specifically on: {step_focus}

Output JSON only:
{{
  "finding": "what you found (1-2 sentences)",
  "evidence": "specific code detail supporting your finding",
  "risk_level": "high" | "medium" | "low" | "none",
  "uncertainty": "what you are NOT sure about (1 sentence or 'none')"
}}"""


SYNTHESIS_PROMPT = """You are synthesizing vulnerability analysis steps to make a final decision.

Code:
```
{code}
```

Analysis plan and results:
{step_results}

Based on ALL the evidence above, make a final vulnerability verdict.

Output JSON only:
{{
  "has_vulnerability": true/false,
  "vulnerability_type": "CWE-XXX: name" or null,
  "reason": "synthesis of evidence (2-3 sentences)",
  "confidence": 0.0-1.0,
  "vulnerable_lines": [{{"line_number": N, "code": "...", "explanation": "..."}}]
}}

Be conservative: only flag as vulnerable if multiple steps found consistent evidence."""


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
            # Fallback: simple 3-step generic plan
            plan = {
                "cwe_suspects": [cwe_hint or "unknown"],
                "dangerous_ops": ["unknown"],
                "analysis_steps": [
                    {"step": 1, "task": "Identify dangerous operations", "focus": "unsafe function calls"},
                    {"step": 2, "task": "Trace input sources", "focus": "external/user input flow"},
                    {"step": 3, "task": "Check defensive measures", "focus": "bounds/null checks"},
                ]
            }

        steps = plan.get("analysis_steps", [])[:3]
        step_results = []
        prior_context = "No prior steps yet."

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
