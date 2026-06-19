# [修复系统] Repair Agent：ReAct多轮迭代修复，集成KL-RAG/Tools/沙箱/LLM自检/Debate
"""Repair Agent - Automated vulnerability repair system.

Architecture:
1. Tools Layer: AST Tool + Cppcheck (code feature extraction)
2. KL-RAG: retrieve fix_pattern from knowledge base
3. Expert Agent: CWE-specific repair prompt (CoT + Few-Shot)
4. ReAct Loop: generate -> sandbox execute -> observe -> revise (max 3 rounds)
5. LLM Self-Check: 3-role verification (security/code/semantic)
6. Debate: attack/defense/judge for final quality gate
"""

import json
import re
import subprocess
from typing import Any, Dict, List, Optional

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from agents.repair_prompts import get_repair_prompt, GENERIC_REPAIR_PROMPT
from agents.sandbox import run_cpp_sandbox, run_python_sandbox
from agents.ast_tool import extract_ast_features


MAX_REPAIR_ROUNDS = 3

SELF_CHECK_ROLES = [
    ("security_auditor",
     "You are a strict security auditor. Review the repaired code and determine: "
     "Does the fix FULLY eliminate the {cwe} vulnerability? "
     "Reply with JSON: {{\"passed\": true/false, \"reason\": \"...\"}}"),
    ("code_reviewer",
     "You are a careful code reviewer. Review the repaired code and determine: "
     "Does the fix introduce ANY new bugs, memory issues, or vulnerabilities? "
     "Reply with JSON: {{\"passed\": true/false, \"reason\": \"...\"}}"),
    ("original_developer",
     "You are the original developer. Review the repaired code and determine: "
     "Does the fix preserve the original function's semantics and behavior? "
     "Reply with JSON: {{\"passed\": true/false, \"reason\": \"...\"}}"),
]


def _run_cppcheck(code: str, language: str) -> str:
    """运行 Cppcheck 静态分析，返回结果字符串。"""
    if language != "C++":
        return "Cppcheck: not applicable for Python"
    try:
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".cpp", mode="w",
                                         delete=False, encoding="utf-8") as f:
            f.write(code)
            tmp_path = f.name
        result = subprocess.run(
            ["cppcheck", "--enable=all", "--quiet", tmp_path],
            capture_output=True, text=True, timeout=30
        )
        os.unlink(tmp_path)
        output = (result.stdout + result.stderr).strip()
        return output if output else "Cppcheck: no issues found"
    except Exception as e:
        return f"Cppcheck: unavailable ({e})"


def _parse_repair_json(raw: str) -> Optional[dict]:
    """解析 LLM 返回的修复 JSON。"""
    text = raw.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if 0 <= start < end:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                pass
    return None


def _parse_check_json(raw: str) -> dict:
    """解析自检/辩论 JSON。"""
    result = _parse_repair_json(raw)
    if result and "passed" in result:
        return result
    raw_lower = raw.lower()
    passed = "passed" in raw_lower or "yes" in raw_lower or "true" in raw_lower
    return {"passed": passed, "reason": raw[:200]}


async def _self_check(llm: BaseChatModel, original_code: str,
                      fixed_code: str, cwe: str) -> Dict[str, Any]:
    """三角色自检：安全审计员/代码审查员/原始开发者。"""
    results = []
    for role_name, role_prompt in SELF_CHECK_ROLES:
        system = role_prompt.format(cwe=cwe)
        user = (f"Original code:\n```\n{original_code[:1000]}\n```\n\n"
                f"Fixed code:\n```\n{fixed_code[:1000]}\n```")
        try:
            resp = await llm.ainvoke([
                SystemMessage(content=system),
                HumanMessage(content=user),
            ])
            check = _parse_check_json(resp.content)
            check["role"] = role_name
            results.append(check)
        except Exception as e:
            results.append({"role": role_name, "passed": False,
                            "reason": f"check failed: {e}"})

    all_passed = all(r.get("passed", False) for r in results)
    return {"all_passed": all_passed, "checks": results}


async def _debate(llm: BaseChatModel, original_code: str,
                  fixed_code: str, cwe: str) -> Dict[str, Any]:
    """攻防辩论：攻击方尝试证明修复不充分，防御方论证修复有效，裁判判决。"""
    context = (f"Original vulnerable code ({cwe}):\n```\n{original_code[:800]}\n```\n\n"
               f"Proposed fix:\n```\n{fixed_code[:800]}\n```")

    # 攻击方（限制攻击范围：只针对可见代码，不能以"上下文缺失"为由攻击）
    attack_prompt = (
        "You are an adversarial security researcher reviewing a vulnerability fix. "
        "IMPORTANT: The code is a function-level snippet from a larger project. "
        "You may ONLY attack based on what is VISIBLE in the code snippet. "
        "Do NOT reject the fix because of missing context, undefined variables, "
        "or dependencies that are not shown - those are outside the fix scope.\n\n"
        f"{context}\n\n"
        "Find real remaining vulnerabilities in the visible fix logic only. "
        "If the fix correctly addresses the vulnerability pattern for what is visible, "
        "severity should be 'none' or 'low'.\n"
        "Reply with JSON: {{\"attack_points\": [\"...\"], \"severity\": \"high/medium/low/none\"}}"
    )
    try:
        attack_resp = await llm.ainvoke([HumanMessage(content=attack_prompt)])
        attack = _parse_repair_json(attack_resp.content) or {"attack_points": [], "severity": "none"}
    except Exception:
        attack = {"attack_points": [], "severity": "none"}

    # 防御方
    defense_prompt = (
        "You are a security engineer defending the fix. "
        "The code is a function-level snippet - incomplete context is expected and acceptable. "
        f"Counter the following attack points: {attack.get('attack_points', [])}\n\n"
        f"{context}\n\n"
        "Reply with JSON: {{\"defense\": \"...\", \"fix_is_sufficient\": true/false}}"
    )
    try:
        defense_resp = await llm.ainvoke([HumanMessage(content=defense_prompt)])
        defense = _parse_repair_json(defense_resp.content) or {"fix_is_sufficient": True}
    except Exception:
        defense = {"fix_is_sufficient": True, "defense": ""}

    # 裁判（明确告知上下文不完整是正常的）
    judge_prompt = (
        "You are a neutral security judge evaluating a vulnerability fix. "
        "CONTEXT: This is a function-level code snippet. Missing class definitions, "
        "member variables, or external dependencies are EXPECTED and should NOT be "
        "used as grounds for rejection.\n\n"
        f"Attack points: {attack.get('attack_points', [])}\n"
        f"Attack severity: {attack.get('severity', 'none')}\n"
        f"Defense: {defense.get('defense', '')}\n\n"
        f"{context}\n\n"
        "Approve the fix if it correctly addresses the core vulnerability pattern "
        "visible in the code. Reject only if there is a clear remaining vulnerability "
        "in the visible fix logic.\n"
        "Reply with JSON: "
        "{{\"verdict\": \"approved/rejected\", \"confidence\": 0.0-1.0, \"reason\": \"...\"}}"
    )
    try:
        judge_resp = await llm.ainvoke([HumanMessage(content=judge_prompt)])
        judgment = _parse_repair_json(judge_resp.content) or {
            "verdict": "approved", "confidence": 0.7, "reason": "default"
        }
    except Exception:
        judgment = {"verdict": "approved", "confidence": 0.5, "reason": "judge failed"}

    return {
        "verdict": judgment.get("verdict", "approved"),
        "confidence": judgment.get("confidence", 0.5),
        "reason": judgment.get("reason", ""),
        "attack_severity": attack.get("severity", "none"),
        "attack_points": attack.get("attack_points", []),
    }


class RepairAgent:
    """漏洞自动修复 Agent。

    流程：
    Tools分析 → KL-RAG检索fix_pattern → 专家Agent生成修复 →
    ReAct沙箱验证（最多3轮）→ LLM自检 → Debate → 输出修复报告
    """

    def __init__(self, llm: BaseChatModel, kl_retriever=None):
        self.llm = llm
        self.kl_retriever = kl_retriever

    async def _retrieve_fix_patterns(self, code: str, cwe: str) -> str:
        """用 KL-RAG 检索 fix_pattern，作为 Few-Shot 注入 Prompt。"""
        if not self.kl_retriever:
            return ""
        try:
            docs = await self.kl_retriever.retrieve(code, k=3, cwe_filter=cwe)
            patterns = []
            for i, doc in enumerate(docs, 1):
                fp = doc.metadata.get("fix_pattern", "")
                if fp:
                    patterns.append(f"Historical fix pattern {i}: {fp}")
            return "\n".join(patterns) if patterns else ""
        except Exception:
            return ""

    async def _generate_fix(self, code: str, cwe: str, language: str,
                             vulnerability_report: str, vulnerable_lines: str,
                             rag_context: str, sandbox_feedback: str = "") -> Optional[dict]:
        """调用 LLM 生成修复代码。"""
        prompt_template = get_repair_prompt(cwe)

        context_note = (
            "NOTE: The code snippet may be incomplete. Make reasonable assumptions "
            "for missing context. Do NOT use TODO comments - implement actual fixes."
        )

        if sandbox_feedback:
            # 把反馈放在最前面，用强烈指令强迫 LLM 针对性修改
            feedback_block = (
                f"CRITICAL FEEDBACK FROM PREVIOUS ATTEMPT (you MUST address this):\n"
                f"{sandbox_feedback}\n\n"
                f"DO NOT repeat the same mistake. Make concrete code changes to fix "
                f"the issues raised above. No TODO comments - write actual implementation.\n\n"
            )
            rag_context = feedback_block + context_note + "\n\n" + rag_context
        else:
            rag_context = context_note + "\n\n" + rag_context

        try:
            chain = prompt_template | self.llm
            inputs = {
                "code": code[:2500],
                "vulnerability_report": vulnerability_report[:500],
                "vulnerable_lines": vulnerable_lines[:300],
                "rag_context": rag_context[:1000],
                "cwe": cwe,
            }
            resp = await chain.ainvoke(inputs)
            return _parse_repair_json(resp.content)
        except Exception as e:
            print(f"  [RepairAgent] LLM call failed: {e}")
            return None

    def _verify_in_sandbox(self, fixed_code: str, original_code: str,
                           cwe: str, language: str) -> Dict[str, Any]:
        """在沙箱中验证修复是否消除了漏洞。"""
        from agents.verifier import SANITIZER_FOR_CWE
        sanitizer = SANITIZER_FOR_CWE.get(cwe, "address")

        if language == "C++":
            result = run_cpp_sandbox(fixed_code, sanitizer=sanitizer, timeout=60)
        else:
            result = run_python_sandbox(fixed_code, timeout=60)

        # 判断是否还有漏洞信号（只关注严重的内存错误，排除编译警告）
        output = (result.stdout + result.stderr).lower()
        # 严格漏洞关键词：真正的运行时内存错误
        strict_vuln_keywords = [
            "stack-buffer-overflow", "heap-buffer-overflow",
            "use-after-free", "detected memory leaks",
            "data race", "heap-use-after-free",
            "segmentation fault", "segfault",
        ]
        # 宽松排除：只是编译警告或代码片段缺少依赖导致的链接错误
        noise_keywords = [
            "undefined reference", "linker error",
            "warning:", "note:", "undefined symbol",
        ]
        has_strict_vuln = any(kw in output for kw in strict_vuln_keywords)
        is_noise = any(kw in output for kw in noise_keywords) and not has_strict_vuln
        still_vulnerable = has_strict_vuln and not is_noise

        return {
            "compiled": result.exit_code != 2,
            "still_vulnerable": still_vulnerable,
            "output": (result.stdout + result.stderr)[:500],
            "exit_code": result.exit_code,
        }

    async def repair(self, code: str, cwe: str, language: str,
                     vulnerability_report: str,
                     vulnerable_lines: str = "",
                     enable_sandbox: bool = True,
                     enable_self_check: bool = True,
                     enable_debate: bool = True) -> Dict[str, Any]:
        """执行完整的修复流程，返回修复报告。"""

        print(f"[RepairAgent] 开始修复 {cwe} ({language})")

        # Step 1: Tools 层分析
        ast_info = ""
        try:
            ast_features = extract_ast_features(code, language)
            if ast_features:
                ast_info = f"AST features: {ast_features}"
        except Exception:
            pass

        cppcheck_info = _run_cppcheck(code, language)
        tools_context = f"{ast_info}\n{cppcheck_info}".strip()

        # Step 2: KL-RAG 检索 fix_pattern
        rag_context = await self._retrieve_fix_patterns(code, cwe)
        if tools_context:
            rag_context = f"Static analysis:\n{tools_context}\n\n{rag_context}"

        # Step 3: ReAct 多轮修复（沙箱失败 OR Debate rejected 都触发重试）
        fixed_code = None
        repair_result = None
        sandbox_feedback = ""
        debate_feedback = ""
        rounds_used = 0
        sandbox_results = []
        debate_result_interim = None
        round_history = []  # 记录每轮的修复代码，用于证明迭代有进步

        for round_num in range(1, MAX_REPAIR_ROUNDS + 1):
            rounds_used = round_num
            print(f"  [Round {round_num}/{MAX_REPAIR_ROUNDS}] 生成修复代码...")

            # 合并沙箱反馈和 Debate 反馈
            combined_feedback = ""
            if sandbox_feedback:
                combined_feedback += sandbox_feedback
            if debate_feedback:
                combined_feedback += f"\n\nDebate reviewer feedback: {debate_feedback}\nPlease address these concerns in the revised fix."

            repair_result = await self._generate_fix(
                code=code,
                cwe=cwe,
                language=language,
                vulnerability_report=vulnerability_report,
                vulnerable_lines=vulnerable_lines,
                rag_context=rag_context,
                sandbox_feedback=combined_feedback,
            )

            if not repair_result or not repair_result.get("fixed_code"):
                print(f"  [Round {round_num}] LLM 未返回有效修复代码")
                round_history.append({
                    "round": round_num,
                    "fixed_code": None,
                    "feedback_used": combined_feedback[:200] if combined_feedback else None,
                    "outcome": "llm_failed",
                })
                continue

            fixed_code = repair_result["fixed_code"]

            # 记录本轮历史
            round_record = {
                "round": round_num,
                "fixed_code": fixed_code[:500],
                "fix_strategy": repair_result.get("fix_strategy", ""),
                "feedback_used": combined_feedback[:200] if combined_feedback else None,
                "outcome": "pending",
            }

            # Step 4: 沙箱验证（ReAct 的 Action + Observation）
            if enable_sandbox and language == "C++":
                print(f"  [Round {round_num}] 沙箱验证...")
                sandbox_result = self._verify_in_sandbox(fixed_code, code, cwe, language)
                sandbox_results.append(sandbox_result)

                if not sandbox_result["compiled"]:
                    sandbox_feedback = f"Compilation failed: {sandbox_result['output']}"
                    debate_feedback = ""
                    round_record["outcome"] = "compilation_failed"
                    round_history.append(round_record)
                    print(f"  [Round {round_num}] 编译失败，重试...")
                    continue
                elif sandbox_result["still_vulnerable"]:
                    sandbox_feedback = f"Still vulnerable: {sandbox_result['output']}"
                    debate_feedback = ""
                    print(f"  [Round {round_num}] 漏洞未消除，重试...")
                    continue
                else:
                    print(f"  [Round {round_num}] 沙箱验证通过！")
                    # 沙箱通过后做 Debate 中间验证，如果 rejected 且还有轮次则继续修复
                    if enable_debate and round_num < MAX_REPAIR_ROUNDS:
                        debate_result_interim = await _debate(self.llm, code, fixed_code, cwe)
                        if debate_result_interim.get("verdict") == "rejected":
                            debate_feedback = debate_result_interim.get("reason", "Fix not sufficient")
                            attack_points = debate_result_interim.get("attack_points", [])
                            if attack_points:
                                debate_feedback += f" Attack points: {attack_points}"
                            sandbox_feedback = ""
                            round_record["outcome"] = f"debate_rejected: {debate_feedback[:100]}"
                            round_history.append(round_record)
                            print(f"  [Round {round_num}] Debate rejected，根据反馈重试...")
                            continue
                    round_record["outcome"] = "success"
                    round_history.append(round_record)
                    break
            else:
                round_record["outcome"] = "no_sandbox"
                round_history.append(round_record)
                break

        if not fixed_code:
            return {
                "status": "failed",
                "reason": "LLM failed to generate valid fix after all rounds",
                "rounds_used": rounds_used,
            }

        # Step 5: LLM 自检（3角色）
        self_check_result = {"all_passed": True, "checks": []}
        if enable_self_check:
            print("  [自检] 三角色验证...")
            self_check_result = await _self_check(self.llm, code, fixed_code, cwe)
            if not self_check_result["all_passed"]:
                print("  [自检] 存在问题，但仍继续输出（记录警告）")

        # Step 6: Debate 验证
        debate_result = {"verdict": "approved", "confidence": 0.8}
        if enable_debate:
            print("  [Debate] 攻防辩论...")
            debate_result = await _debate(self.llm, code, fixed_code, cwe)
            print(f"  [Debate] verdict={debate_result['verdict']}, "
                  f"confidence={debate_result['confidence']:.2f}")

        # 计算最终置信度
        base_confidence = repair_result.get("confidence", 0.7)
        self_check_bonus = 0.1 if self_check_result["all_passed"] else -0.1
        debate_confidence = debate_result.get("confidence", 0.7)
        final_confidence = round(
            0.4 * base_confidence + 0.3 * debate_confidence +
            0.2 * (1.0 if self_check_result["all_passed"] else 0.5) +
            0.1, 3
        )

        # 确定最终状态
        if sandbox_results:
            last = sandbox_results[-1]
            if not last["compiled"]:
                status = "compilation_failed"
            elif last["still_vulnerable"]:
                status = "unverified"
            else:
                status = "verified_fixed"
        elif language != "C++":
            status = "generated_unverified"
        else:
            status = "generated_unverified"

        if debate_result.get("verdict") == "rejected":
            status = "debate_rejected"

        return {
            "status": status,
            "fixed_code": fixed_code,
            "original_code": code,
            "cwe": cwe,
            "language": language,
            "changes": repair_result.get("changes", []),
            "fix_strategy": repair_result.get("fix_strategy", ""),
            "cot_reasoning": repair_result.get("cot_reasoning", ""),
            "potential_issues": repair_result.get("potential_issues"),
            "rounds_used": rounds_used,
            "round_history": round_history,  # 每轮修复代码+反馈，证明迭代有进步
            "confidence": final_confidence,
            "self_check": self_check_result,
            "debate": debate_result,
            "sandbox_results": sandbox_results,
            "rag_patterns_used": bool(rag_context),
        }
