# [C3: Verification Agent] 生成PoC代码并在Docker沙箱执行，解析ASan/TSan报告，输出confirmed/suspected/unverifiable/not_reproduced四档verdict
"""Verification Agent - Generate PoC and verify vulnerability via sandbox execution.

This is the most distinctive agent in the system. It:
1. Takes a Detection Agent's vulnerability claim
2. Asks LLM to generate a PoC (with stubs for ROS dependencies)
3. Compiles and runs the PoC in Docker sandbox with sanitizers
4. Parses sanitizer output as runtime evidence
5. Returns a graded verdict: confirmed / suspected / unverifiable / not_reproduced
"""

import re
from typing import Dict, Any, Optional

from langchain_core.language_models import BaseChatModel
from langchain_core.prompts import ChatPromptTemplate

from agents.sandbox import (
    run_cpp_sandbox,
    run_python_sandbox,
    SandboxResult,
)


SANITIZER_FOR_CWE = {
    "CWE-119": "address",
    "CWE-476": "address",
    "CWE-401": "address",
    "CWE-416": "address",
    "CWE-362": "thread",
    "CWE-190": "undefined",
    "CWE-134": "address",
    "CWE-78": "address",
}


POC_GEN_PROMPT_CPP = ChatPromptTemplate.from_messages([
    ("system", """You are a security researcher writing a minimal Proof-of-Concept (PoC).

Given a vulnerable function and a vulnerability report, write a SELF-CONTAINED C++ program that:
1. Includes all needed headers
2. Stubs any ROS/external types with minimal mocks (e.g., struct Msg {{ std::string data; using ConstPtr = std::shared_ptr<const Msg>; }})
3. Copies the original function VERBATIM
4. Has a main() that calls the function with malicious input designed to TRIGGER the {cwe} vulnerability

The program must compile with: g++ -std=c++17 -fsanitize=address -g -O0
The PoC will be run with AddressSanitizer to detect memory errors.

For CWE-119: feed oversized input to overflow buffer
For CWE-476: pass NULL or empty pointer
For CWE-401: don't matter - leak detected at exit
For CWE-416: trigger free then access
For CWE-78: pass shell-injection payload
For CWE-190: pass values causing arithmetic overflow

Output ONLY the C++ source code. No explanations, no markdown fences."""),
    ("user", """Vulnerable function:
```cpp
{code}
```

Vulnerability report:
- Type: {cwe}
- Reason: {reason}

Generate the PoC C++ program:"""),
])


POC_GEN_PROMPT_PY = ChatPromptTemplate.from_messages([
    ("system", """You are a security researcher writing a minimal Proof-of-Concept (PoC).

Given a vulnerable Python function and a vulnerability report, write a SELF-CONTAINED Python program that:
1. Imports needed modules
2. Stubs any ROS/external types with minimal mocks
3. Copies the original function VERBATIM
4. Has code that calls the function with malicious input designed to TRIGGER the {cwe} vulnerability

Output ONLY the Python source code. No explanations, no markdown fences."""),
    ("user", """Vulnerable function:
```python
{code}
```

Vulnerability report:
- Type: {cwe}
- Reason: {reason}

Generate the PoC Python program:"""),
])


class VerificationAgent:
    """Generates PoC and runs it in sandbox to verify vulnerability claims."""

    def __init__(self, llm: BaseChatModel, max_retries: int = 2):
        self.llm = llm
        self.max_retries = max_retries

    async def verify(
        self,
        code: str,
        cwe: str,
        reason: str,
        language: str = "C++",
    ) -> Dict[str, Any]:
        """Verify a vulnerability claim by PoC execution.

        Returns:
            {
                "verified": "confirmed" | "suspected" | "unverifiable" | "not_reproduced",
                "confidence": float,
                "poc_code": str (the generated PoC),
                "evidence": str (sanitizer output excerpt),
                "sandbox_result": SandboxResult dict,
                "attempts": int
            }
        """
        if language not in ("C++", "Python"):
            return {
                "verified": "unverifiable",
                "confidence": 0.3,
                "poc_code": "",
                "evidence": f"Unsupported language: {language}",
                "sandbox_result": None,
                "attempts": 0,
            }

        is_cpp = language == "C++"
        prompt = POC_GEN_PROMPT_CPP if is_cpp else POC_GEN_PROMPT_PY
        sanitizer = SANITIZER_FOR_CWE.get(cwe, "address")

        last_result: Optional[SandboxResult] = None
        last_poc = ""

        for attempt in range(1, self.max_retries + 1):
            chain = prompt | self.llm
            response = await chain.ainvoke({
                "code": code[:2500],
                "cwe": cwe,
                "reason": reason[:500],
            })
            poc_code = self._extract_code(response.content, is_cpp)
            last_poc = poc_code

            if is_cpp:
                result = run_cpp_sandbox(poc_code, sanitizer=sanitizer, timeout=30)
            else:
                result = run_python_sandbox(poc_code, timeout=30)
            last_result = result

            if result.compile_failed:
                if attempt < self.max_retries:
                    continue
                return self._make_verdict(
                    "unverifiable",
                    confidence=0.3,
                    poc_code=poc_code,
                    evidence=f"Compile failed after {attempt} attempts:\n{result.stderr[:500]}",
                    sandbox_result=result,
                    attempts=attempt,
                )

            if result.has_runtime_evidence():
                return self._make_verdict(
                    "confirmed",
                    confidence=0.95,
                    poc_code=poc_code,
                    evidence=result.asan_keyword or "Sanitizer triggered",
                    sandbox_result=result,
                    attempts=attempt,
                )

            if result.timed_out:
                return self._make_verdict(
                    "suspected",
                    confidence=0.5,
                    poc_code=poc_code,
                    evidence="Execution timed out (possible infinite loop / deadlock)",
                    sandbox_result=result,
                    attempts=attempt,
                )

            if result.exit_code != 0:
                return self._make_verdict(
                    "suspected",
                    confidence=0.6,
                    poc_code=poc_code,
                    evidence=f"Non-zero exit (code={result.exit_code}) without explicit sanitizer report",
                    sandbox_result=result,
                    attempts=attempt,
                )

        return self._make_verdict(
            "not_reproduced",
            confidence=0.4,
            poc_code=last_poc,
            evidence="PoC executed successfully without triggering the vulnerability",
            sandbox_result=last_result,
            attempts=self.max_retries,
        )

    def _extract_code(self, raw: str, is_cpp: bool) -> str:
        """Extract code from LLM response, stripping markdown fences."""
        text = raw.strip()
        fence_pattern = r"```(?:cpp|c\+\+|python|py)?\s*\n(.*?)```"
        match = re.search(fence_pattern, text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return text

    def _make_verdict(self, verified, confidence, poc_code, evidence, sandbox_result, attempts):
        return {
            "verified": verified,
            "confidence": confidence,
            "poc_code": poc_code,
            "evidence": evidence,
            "sandbox_result": {
                "exit_code": sandbox_result.exit_code if sandbox_result else None,
                "compile_failed": sandbox_result.compile_failed if sandbox_result else None,
                "asan_triggered": sandbox_result.asan_triggered if sandbox_result else False,
                "tsan_triggered": sandbox_result.tsan_triggered if sandbox_result else False,
                "ubsan_triggered": sandbox_result.ubsan_triggered if sandbox_result else False,
                "leak_detected": sandbox_result.leak_detected if sandbox_result else False,
                "stderr_excerpt": (sandbox_result.stderr[:500] if sandbox_result else ""),
            } if sandbox_result else None,
            "attempts": attempts,
        }
