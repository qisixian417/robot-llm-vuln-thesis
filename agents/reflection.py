# [C7: Reflection Agent] 检测后自我反思：审查is_vulnerability=True的判断是否有充分证据，降低误报（实验显示在本数据集有害，作为负向发现保留）
"""Reflection Agent - self-correction after Detection.

After Detection reports a vulnerability, the Reflection Agent reviews
the reasoning and asks: "Is this verdict well-supported?"

Specifically targets FALSE POSITIVES by checking:
1. Are there existing defensive checks in the code (null checks, bounds)?
2. Is the vulnerable operation actually reachable?
3. Is the input truly user-controlled (vs constant/local)?
4. Does the reasoning logically support the CWE type claimed?

Only triggers when:
- has_vulnerability = True (no point checking "clean" verdicts)
- confidence < reflection_threshold (high-confidence verdicts likely correct)

Reference: Reflexion (Shinn et al., NeurIPS 2023)
"""

import json
import re
from typing import Dict, Any, Optional

from langchain_core.language_models import BaseChatModel
from langchain_core.prompts import ChatPromptTemplate


REFLECTION_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a senior security code reviewer performing a second-pass audit.

A junior auditor just flagged the following code as vulnerable. Your job is to critically
review their verdict and decide: is this a real vulnerability, or a false positive?

Focus on false positive indicators:
- Is there ALREADY a null/bounds check protecting the flagged operation?
- Is the "vulnerable" input actually a constant, local variable, or otherwise not user-controlled?
- Is the flagged code inside a conditional that prevents the dangerous path?
- Does the stated CWE type actually match what the code does?
- Is the vulnerability triggerable in practice, or only in theory?

Be strict: only CONFIRM if you see clear, unambiguous evidence of the vulnerability.
If in doubt, REVISE to lower confidence or REJECT the verdict.

Output JSON only:
{{
  "decision": "confirm" | "revise" | "reject",
  "reason": "1-2 sentences explaining your decision",
  "revised_confidence": 0.0-1.0,
  "key_evidence": "the specific code detail that determined your decision"
}}

- "confirm": evidence clearly supports the vulnerability claim
- "revise": vulnerability might exist but original confidence is too high, lower it
- "reject": likely a false positive, insufficient evidence for the claimed vulnerability"""),
    ("user", """Original code:
```
{code}
```

Junior auditor's verdict:
- Vulnerability type: {vuln_type}
- Flagged lines: {flagged_lines}
- Reasoning: {reason}
- Confidence: {confidence}

Your critical review:"""),
])


class ReflectionAgent:
    """Reviews Detection verdicts to reduce false positives."""

    def __init__(self, llm: BaseChatModel, reflection_threshold: float = 0.85):
        self.llm = llm
        self.reflection_threshold = reflection_threshold
        self.chain = REFLECTION_PROMPT | self.llm

    async def reflect(
        self,
        code: str,
        detection_output: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Review a Detection verdict and potentially revise it.

        Returns the (possibly updated) detection output dict.
        Adds 'reflection_applied', 'reflection_decision', 'reflection_reason' fields.
        """
        has_vuln = detection_output.get("has_vulnerability", False)
        confidence = float(detection_output.get("confidence", 0))

        # Skip if: not flagged as vulnerable, or very high confidence
        if not has_vuln:
            detection_output["reflection_applied"] = False
            detection_output["reflection_decision"] = "skipped_clean"
            return detection_output

        if confidence >= self.reflection_threshold:
            detection_output["reflection_applied"] = False
            detection_output["reflection_decision"] = "skipped_high_confidence"
            return detection_output

        # Extract fields for the reflection prompt
        vuln_type = detection_output.get("vulnerability_type") or "Unknown"
        reason = (detection_output.get("reason") or "")[:400]
        flagged_lines = detection_output.get("vulnerable_lines", [])
        lines_str = ", ".join(
            f"L{l.get('line_number', '?')}: {l.get('code', '')[:60]}"
            for l in flagged_lines[:3]
        ) or "Not specified"

        try:
            response = await self.chain.ainvoke({
                "code": code[:2500],
                "vuln_type": vuln_type,
                "flagged_lines": lines_str,
                "reason": reason,
                "confidence": f"{confidence:.2f}",
            })
            reflection = self._parse_response(response.content)
        except Exception as e:
            # If reflection fails, keep original verdict unchanged
            detection_output["reflection_applied"] = False
            detection_output["reflection_decision"] = f"error: {e}"
            return detection_output

        # Apply reflection decision
        decision = reflection.get("decision", "confirm")
        detection_output["reflection_applied"] = True
        detection_output["reflection_decision"] = decision
        detection_output["reflection_reason"] = reflection.get("reason", "")
        detection_output["reflection_key_evidence"] = reflection.get("key_evidence", "")

        if decision == "reject":
            detection_output["has_vulnerability"] = False
            detection_output["confidence"] = reflection.get("revised_confidence", 0.2)
        elif decision == "revise":
            new_conf = reflection.get("revised_confidence", confidence * 0.6)
            detection_output["confidence"] = min(new_conf, confidence)
        # "confirm": keep original verdict, possibly update confidence
        else:
            revised = reflection.get("revised_confidence", confidence)
            detection_output["confidence"] = max(confidence, revised)

        return detection_output

    def _parse_response(self, raw: str) -> Dict[str, Any]:
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
        # fallback: try to extract decision from text
        text_lower = text.lower()
        if "reject" in text_lower:
            return {"decision": "reject", "reason": text[:200], "revised_confidence": 0.2}
        elif "revise" in text_lower:
            return {"decision": "revise", "reason": text[:200], "revised_confidence": 0.4}
        return {"decision": "confirm", "reason": text[:200], "revised_confidence": 0.7}
