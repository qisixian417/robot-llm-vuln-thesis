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
    ("system", """你是一位安全研究员，正在编写最简化的概念验证（PoC）程序。

给定一个有漏洞的函数和漏洞报告，编写一个完全独立的C++程序，该程序需要：
1. 包含所有需要的头文件
2. 对ROS/外部类型用最小化mock代替（例如：struct Msg {{ std::string data; using ConstPtr = std::shared_ptr<const Msg>; }}）
3. 原封不动地复制原始函数
4. 有一个main()函数，用恶意输入调用该函数以触发{cwe}漏洞

程序必须能用以下命令编译：g++ -std=c++17 -fsanitize=address -g -O0
PoC将在AddressSanitizer下运行以检测内存错误。

各CWE的触发方式：
- CWE-119：输入超长数据使缓冲区溢出
- CWE-476：传入NULL或空指针
- CWE-401：无需特别处理，程序退出时会检测到泄漏
- CWE-416：先触发free然后访问
- CWE-78：传入shell注入载荷
- CWE-190：传入会导致算术溢出的值

只输出C++源代码，不要任何解释，不要markdown代码块。"""),
    ("user", """有漏洞的函数：
```cpp
{code}
```

漏洞报告：
- 类型：{cwe}
- 原因：{reason}

生成PoC C++程序："""),
])


POC_GEN_PROMPT_PY = ChatPromptTemplate.from_messages([
    ("system", """你是一位安全研究员，正在编写最简化的概念验证（PoC）程序。

给定一个有漏洞的Python函数和漏洞报告，编写一个完全独立的Python程序，该程序需要：
1. 导入所有需要的模块
2. 对ROS/外部类型用最小化mock代替
3. 原封不动地复制原始函数
4. 有代码用恶意输入调用该函数以触发{cwe}漏洞

只输出Python源代码，不要任何解释，不要markdown代码块。"""),
    ("user", """有漏洞的函数：
```python
{code}
```

漏洞报告：
- 类型：{cwe}
- 原因：{reason}

生成PoC Python程序："""),
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
