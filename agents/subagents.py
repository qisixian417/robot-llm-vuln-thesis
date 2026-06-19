# [C5+C6: Subagent投票与辩论] VotingSubagents：3个不同人设独立判断投票（降低误报）；DebateSubagents：多轮辩论达共识（实验中有害，作为负向发现保留）
"""Subagent voting and debate mechanisms.

Two modes:
- Voting: N independent subagents (different personas) judge the code,
  result is determined by majority vote (Self-Consistency, Wang et al. ICLR 2023)
- Debate: subagents iterate, reviewing each other's reasoning until consensus
  (Multi-Agent Debate, Du et al. ICML 2024)
"""

import asyncio
import json
import re
from typing import Dict, Any, List, Optional

from langchain_core.language_models import BaseChatModel
from langchain_core.prompts import ChatPromptTemplate

from agents.cwe_prompts import get_prompt_for_cwe


PERSONAS = {
    "conservative": (
        "你是一位以严谨、基于证据著称的资深安全审计员。"
        "只有在有明确证据证明存在不安全模式时才标记漏洞。"
        "宁可漏报，不可误报。"
    ),
    "aggressive": (
        "你是一位假设最坏情况的攻击性安全研究员。"
        "对任何在对抗性输入下可能被利用的模式都标记出来。"
        "宁可误报，不可漏报。"
    ),
    "balanced": (
        "你是一位均衡的安全分析师。根据观察到的模式判断代码，"
        "不偏向过度报告或漏报。"
    ),
}


def _persona_system(base_system: str, persona_text: str) -> str:
    return f"{persona_text}\n\n{base_system}"


def _build_persona_prompt(cwe_hint: str, persona: str) -> ChatPromptTemplate:
    """Wrap a CWE-specific prompt with a persona system prefix."""
    base = get_prompt_for_cwe(cwe_hint)
    persona_text = PERSONAS[persona]

    base_messages = base.messages
    base_system = base_messages[0].prompt.template
    user_template = base_messages[1].prompt.template

    return ChatPromptTemplate.from_messages([
        ("system", _persona_system(base_system, persona_text)),
        ("user", user_template),
    ])


def _parse_json(raw_text: str) -> Dict[str, Any]:
    text = raw_text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"```\s*$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            start = text.find("{")
            end = text.rfind("}")
            if 0 <= start < end:
                return json.loads(text[start:end+1])
        except json.JSONDecodeError:
            pass
    return {
        "has_vulnerability": False,
        "vulnerability_type": None,
        "reason": "parse_error",
        "confidence": 0.0,
    }


def _format_context(docs: List) -> str:
    if not docs:
        return "No relevant historical cases found."
    parts = []
    for i, doc in enumerate(docs):
        content = getattr(doc, "page_content", str(doc))
        meta = getattr(doc, "metadata", {})
        cwe = meta.get("cwe_id", "?")
        parts.append(f"Case {i+1} [{cwe}]:\n{content[:400]}")
    return "\n\n".join(parts)


class VotingSubagents:
    """Run N subagents independently and vote on the verdict."""

    def __init__(self, llm: BaseChatModel, personas: Optional[List[str]] = None):
        self.llm = llm
        self.personas = personas or ["conservative", "aggressive", "balanced"]

    async def judge(
        self,
        code: str,
        cwe_hint: Optional[str],
        rag_documents: Optional[List] = None,
    ) -> Dict[str, Any]:
        """Each subagent judges independently; aggregate by majority vote."""
        cwe = cwe_hint or "OTHER"
        context = _format_context(rag_documents or [])
        numbered = "\n".join(
            f"L{i+1}: {line}" for i, line in enumerate(code.splitlines())
        )

        async def run_one(persona: str) -> Dict[str, Any]:
            prompt = _build_persona_prompt(cwe, persona)
            chain = prompt | self.llm
            response = await chain.ainvoke({"code": numbered, "context": context})
            parsed = _parse_json(response.content)
            parsed["_persona"] = persona
            return parsed

        opinions = await asyncio.gather(*(run_one(p) for p in self.personas))
        return self._aggregate(opinions)

    def _aggregate(self, opinions: List[Dict[str, Any]]) -> Dict[str, Any]:
        votes_yes = [o for o in opinions if o.get("has_vulnerability")]
        votes_no = [o for o in opinions if not o.get("has_vulnerability")]

        majority_yes = len(votes_yes) > len(votes_no)
        n = len(opinions)
        agreement = max(len(votes_yes), len(votes_no)) / n if n else 0

        if majority_yes:
            confidences = [float(o.get("confidence", 0.5)) for o in votes_yes]
            avg_conf = sum(confidences) / len(confidences) if confidences else 0.5
            cwes = [o.get("vulnerability_type") for o in votes_yes if o.get("vulnerability_type")]
            chosen_cwe = max(set(cwes), key=cwes.count) if cwes else None
            reason = votes_yes[0].get("reason", "")
            lines = votes_yes[0].get("vulnerable_lines", [])
        else:
            confidences = [float(o.get("confidence", 0.5)) for o in votes_no]
            avg_conf = sum(confidences) / len(confidences) if confidences else 0.5
            chosen_cwe = None
            reason = votes_no[0].get("reason", "") if votes_no else ""
            lines = []

        # Self-consistency confidence: scale by agreement ratio
        final_conf = avg_conf * agreement

        return {
            "has_vulnerability": majority_yes,
            "vulnerability_type": chosen_cwe,
            "reason": reason,
            "confidence": round(final_conf, 4),
            "vulnerable_lines": lines,
            "voting_details": {
                "n_yes": len(votes_yes),
                "n_no": len(votes_no),
                "agreement": round(agreement, 4),
                "personas": [o.get("_persona") for o in opinions],
            },
        }


DEBATE_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a security auditor in a debate with peer auditors about a code snippet.

Below are previous round opinions from yourself and other auditors. Reconsider your judgment:
- If you agree with the majority, restate your verdict with stronger evidence.
- If you disagree, provide a counter-argument with specific code references.

You may change your mind if other auditors raise valid points.

Output JSON only:
{{
  "has_vulnerability": true/false,
  "vulnerability_type": "CWE-XXX" or null,
  "reason": "your updated reasoning",
  "confidence": 0.0-1.0
}}"""),
    ("user", """Code:
{code}

Reference cases:
{context}

Previous round opinions:
{prior_opinions}

Your role: {persona}
Your previous opinion: {your_prior}

Provide your updated verdict:"""),
])


class DebateSubagents:
    """Run multiple rounds of debate among subagents until consensus or max rounds."""

    def __init__(
        self,
        llm: BaseChatModel,
        personas: Optional[List[str]] = None,
        max_rounds: int = 3,
    ):
        self.llm = llm
        self.personas = personas or ["conservative", "aggressive", "balanced"]
        self.max_rounds = max_rounds
        self._voting = VotingSubagents(llm, personas)

    async def judge(
        self,
        code: str,
        cwe_hint: Optional[str],
        rag_documents: Optional[List] = None,
    ) -> Dict[str, Any]:
        """Run iterative debate; return final aggregated verdict."""
        # Round 1: independent judgments (same as voting)
        round1 = await self._voting.judge(code, cwe_hint, rag_documents)
        round1_opinions = self._opinions_from_voting(round1)

        rounds = [{"round": 1, "verdict": round1}]
        history = round1_opinions

        for r in range(2, self.max_rounds + 1):
            new_history = await self._debate_round(
                code, cwe_hint, rag_documents, history,
            )
            agg = self._voting._aggregate(new_history)
            rounds.append({"round": r, "verdict": agg})

            # Check consensus (>= 90% agreement)
            if agg["voting_details"]["agreement"] >= 0.99:
                break
            history = new_history

        final = rounds[-1]["verdict"]
        final["debate_rounds"] = len(rounds)
        final["debate_trace"] = [
            {
                "round": r["round"],
                "yes_votes": r["verdict"]["voting_details"]["n_yes"],
                "no_votes": r["verdict"]["voting_details"]["n_no"],
            }
            for r in rounds
        ]
        return final

    async def _debate_round(self, code, cwe_hint, rag_documents, prior_opinions):
        context = _format_context(rag_documents or [])
        numbered = "\n".join(
            f"L{i+1}: {line}" for i, line in enumerate(code.splitlines())
        )

        prior_summary = self._summarize_prior(prior_opinions)

        async def run_one(prior_op):
            persona = prior_op["_persona"]
            chain = DEBATE_PROMPT | self.llm
            response = await chain.ainvoke({
                "code": numbered,
                "context": context,
                "prior_opinions": prior_summary,
                "persona": persona,
                "your_prior": json.dumps({
                    "has_vulnerability": prior_op.get("has_vulnerability"),
                    "reason": prior_op.get("reason", "")[:200],
                }, ensure_ascii=False),
            })
            parsed = _parse_json(response.content)
            parsed["_persona"] = persona
            return parsed

        return await asyncio.gather(*(run_one(p) for p in prior_opinions))

    def _opinions_from_voting(self, voting_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        details = voting_result.get("voting_details", {})
        personas = details.get("personas", self.personas)
        opinions = []
        for p in personas:
            opinions.append({
                "_persona": p,
                "has_vulnerability": voting_result.get("has_vulnerability"),
                "reason": voting_result.get("reason", ""),
                "confidence": voting_result.get("confidence", 0.5),
                "vulnerability_type": voting_result.get("vulnerability_type"),
            })
        return opinions

    def _summarize_prior(self, opinions: List[Dict[str, Any]]) -> str:
        parts = []
        for o in opinions:
            verdict = "VULNERABLE" if o.get("has_vulnerability") else "CLEAN"
            persona = o.get("_persona", "?")
            reason = (o.get("reason") or "")[:150]
            parts.append(f"[{persona}] {verdict}: {reason}")
        return "\n".join(parts)
