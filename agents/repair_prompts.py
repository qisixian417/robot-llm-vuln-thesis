# [修复系统] CWE专用修复Prompt：7种CWE各有专属修复指令，含CoT推理链和Few-Shot示例
"""CWE-specific repair prompt templates.

Each template contains:
1. Few-Shot: 2 historical repair examples (before/after)
2. CoT: 4-step reasoning chain for repair
3. CWE-specific repair patterns and anti-patterns
"""

from langchain_core.prompts import ChatPromptTemplate

# ── 共享修复CoT推理链 ─────────────────────────────────────────────────────────

_REPAIR_COT = (
    "\nBefore generating the fix, reason step by step:\n"
    "1. ROOT CAUSE: What exactly is the vulnerability root cause?\n"
    "2. STRATEGY: What is the minimal fix strategy? (based on historical patterns)\n"
    "3. GENERATE: Write the fixed code, changing as few lines as possible\n"
    "4. VERIFY: Does the fix eliminate the root cause without introducing new issues?\n"
)

_REPAIR_FMT = (
    "\nYou MUST output valid JSON only. No markdown fences, no explanation outside JSON.\n"
    "Start your response with {{ and end with }}.\n"
    "Example format:\n"
    '{{"fixed_code": "void foo() {{\\n  // fixed code here\\n}}", '
    '"changes": [{{"line": 5, "original": "bad code", "fixed": "good code", "reason": "why"}}], '
    '"fix_strategy": "one sentence", '
    '"confidence": 0.8, '
    '"cot_reasoning": "brief reasoning", '
    '"potential_issues": null}}\n'
)


def _sys(body: str) -> str:
    return body + _REPAIR_COT + "{rag_context}\n" + _REPAIR_FMT


# ── CWE-476: Null Pointer Dereference ────────────────────────────────────────

_476_BODY = (
    "You are a security expert fixing CWE-476 (Null Pointer Dereference).\n\n"
    "REPAIR EXAMPLE 1:\n"
    "Before: node->value = 42;  // no null check\n"
    "After:  if (node != nullptr) {{ node->value = 42; }}\n"
    "Pattern: Add null check before every pointer dereference.\n\n"
    "REPAIR EXAMPLE 2:\n"
    "Before: return ptr->data.c_str();\n"
    "After:  if (!ptr) {{ return \"\"; }}\n"
    "        return ptr->data.c_str();\n"
    "Pattern: Early return or exception when pointer is null.\n\n"
    "ANTI-PATTERNS TO AVOID:\n"
    "- Do not use assert() - it's disabled in release builds\n"
    "- Do not silently ignore null - return error or throw exception\n"
)

CWE476_REPAIR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_476_BODY)),
    ("user", "Vulnerable code (CWE-476):\n```\n{code}\n```\n\n"
             "Vulnerability report: {vulnerability_report}\n"
             "Vulnerable lines: {vulnerable_lines}"),
])


# ── CWE-401: Memory Leak ──────────────────────────────────────────────────────

_401_BODY = (
    "You are a security expert fixing CWE-401 (Memory Leak).\n\n"
    "REPAIR EXAMPLE 1:\n"
    "Before: char* buf = new char[size]; process(buf);  // no delete\n"
    "After:  char* buf = new char[size]; process(buf); delete[] buf;\n"
    "Pattern: Ensure every allocation has a corresponding deallocation.\n\n"
    "REPAIR EXAMPLE 2 (prefer RAII):\n"
    "Before: Node* n = new Node(); return n->value;\n"
    "After:  auto n = std::make_unique<Node>(); return n->value;\n"
    "Pattern: Use smart pointers (unique_ptr/shared_ptr) to auto-manage memory.\n\n"
    "ANTI-PATTERNS TO AVOID:\n"
    "- Do not add delete in only one branch of if/else\n"
    "- Prefer std::unique_ptr over raw new/delete in C++\n"
)

CWE401_REPAIR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_401_BODY)),
    ("user", "Vulnerable code (CWE-401):\n```\n{code}\n```\n\n"
             "Vulnerability report: {vulnerability_report}\n"
             "Vulnerable lines: {vulnerable_lines}"),
])


# ── CWE-362: Race Condition ───────────────────────────────────────────────────

_362_BODY = (
    "You are a security expert fixing CWE-362 (Race Condition).\n\n"
    "REPAIR EXAMPLE 1:\n"
    "Before: shared_counter++;  // unprotected shared variable\n"
    "After:  std::lock_guard<std::mutex> lock(mtx); shared_counter++;\n"
    "Pattern: Protect all shared variable accesses with mutex.\n\n"
    "REPAIR EXAMPLE 2:\n"
    "Before: if (data_ready) {{ process(data); }}\n"
    "After:  std::unique_lock<std::mutex> lock(mtx);\n"
    "        cv.wait(lock, []{{ return data_ready; }});\n"
    "        process(data);\n"
    "Pattern: Use condition variables for thread synchronization.\n\n"
    "ANTI-PATTERNS TO AVOID:\n"
    "- Do not use volatile as a substitute for mutex\n"
    "- Do not assume operations are atomic without std::atomic\n"
)

CWE362_REPAIR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_362_BODY)),
    ("user", "Vulnerable code (CWE-362):\n```\n{code}\n```\n\n"
             "Vulnerability report: {vulnerability_report}\n"
             "Vulnerable lines: {vulnerable_lines}"),
])


# ── CWE-416: Use After Free ───────────────────────────────────────────────────

_416_BODY = (
    "You are a security expert fixing CWE-416 (Use After Free).\n\n"
    "REPAIR EXAMPLE 1:\n"
    "Before: delete ptr; ptr->method();  // use after free\n"
    "After:  delete ptr; ptr = nullptr;  // set to null after free\n"
    "Pattern: Set pointer to nullptr immediately after delete.\n\n"
    "REPAIR EXAMPLE 2:\n"
    "Before: free(buf); return buf[0];  // use after free\n"
    "After:  char result = buf[0]; free(buf); return result;\n"
    "Pattern: Extract needed values before freeing memory.\n\n"
    "ANTI-PATTERNS TO AVOID:\n"
    "- Never access memory after free, even for 'cleanup'\n"
    "- Prefer std::unique_ptr to eliminate manual free entirely\n"
)

CWE416_REPAIR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_416_BODY)),
    ("user", "Vulnerable code (CWE-416):\n```\n{code}\n```\n\n"
             "Vulnerability report: {vulnerability_report}\n"
             "Vulnerable lines: {vulnerable_lines}"),
])


# ── CWE-119: Buffer Overflow ──────────────────────────────────────────────────

_119_BODY = (
    "You are a security expert fixing CWE-119 (Buffer Overflow).\n\n"
    "REPAIR EXAMPLE 1:\n"
    "Before: strcpy(buf, input);  // no length check\n"
    "After:  strncpy(buf, input, sizeof(buf)-1); buf[sizeof(buf)-1] = '\\0';\n"
    "Pattern: Replace unsafe string functions with bounded variants.\n\n"
    "REPAIR EXAMPLE 2:\n"
    "Before: memcpy(dst, src, user_len);  // user-controlled length\n"
    "After:  size_t safe_len = std::min(user_len, sizeof(dst));\n"
    "        memcpy(dst, src, safe_len);\n"
    "Pattern: Validate and bound user-controlled sizes before use.\n\n"
    "ANTI-PATTERNS TO AVOID:\n"
    "- strncpy does not guarantee null termination - always add it\n"
    "- Do not use sprintf - use snprintf instead\n"
)

CWE119_REPAIR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_119_BODY)),
    ("user", "Vulnerable code (CWE-119):\n```\n{code}\n```\n\n"
             "Vulnerability report: {vulnerability_report}\n"
             "Vulnerable lines: {vulnerable_lines}"),
])


# ── CWE-190: Integer Overflow ─────────────────────────────────────────────────

_190_BODY = (
    "You are a security expert fixing CWE-190 (Integer Overflow).\n\n"
    "REPAIR EXAMPLE 1:\n"
    "Before: int size = a + b; char* buf = new char[size];\n"
    "After:  if (a > INT_MAX - b) {{ throw std::overflow_error(\"overflow\"); }}\n"
    "        int size = a + b; char* buf = new char[size];\n"
    "Pattern: Check for overflow before arithmetic operations.\n\n"
    "REPAIR EXAMPLE 2:\n"
    "Before: uint32_t len = data_len * item_size;\n"
    "After:  if (item_size != 0 && data_len > UINT32_MAX / item_size)\n"
    "            return ERROR;\n"
    "        uint32_t len = data_len * item_size;\n"
    "Pattern: Validate multiplication won't overflow before computing.\n\n"
    "ANTI-PATTERNS TO AVOID:\n"
    "- Do not cast to larger type after overflow has already occurred\n"
    "- Use size_t for sizes, not int\n"
)

CWE190_REPAIR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_190_BODY)),
    ("user", "Vulnerable code (CWE-190):\n```\n{code}\n```\n\n"
             "Vulnerability report: {vulnerability_report}\n"
             "Vulnerable lines: {vulnerable_lines}"),
])


# ── CWE-134: Format String ────────────────────────────────────────────────────

_134_BODY = (
    "You are a security expert fixing CWE-134 (Format String).\n\n"
    "REPAIR EXAMPLE 1:\n"
    "Before: printf(user_input);  // user controls format string\n"
    "After:  printf(\"%s\", user_input);  // fixed format string\n"
    "Pattern: Always use a literal format string, never user-controlled.\n\n"
    "REPAIR EXAMPLE 2:\n"
    "Before: fprintf(log, msg);  // user-controlled msg as format\n"
    "After:  fprintf(log, \"%s\", msg);  // msg treated as data only\n"
    "Pattern: Pass user input as argument, not as format string.\n\n"
    "ANTI-PATTERNS TO AVOID:\n"
    "- Never pass user-controlled strings as format argument to printf family\n"
    "- This applies to sprintf, fprintf, snprintf, syslog, etc.\n"
)

CWE134_REPAIR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_134_BODY)),
    ("user", "Vulnerable code (CWE-134):\n```\n{code}\n```\n\n"
             "Vulnerability report: {vulnerability_report}\n"
             "Vulnerable lines: {vulnerable_lines}"),
])


# ── CWE-78: Command Injection ─────────────────────────────────────────────────

_78_BODY = (
    "You are a security expert fixing CWE-78 (Command Injection).\n\n"
    "REPAIR EXAMPLE 1:\n"
    "Before: system((\"ls \" + user_input).c_str());\n"
    "After:  // Use execv with argument array instead of system()\n"
    "        const char* args[] = {{\"ls\", user_input.c_str(), nullptr}};\n"
    "        execv(\"/bin/ls\", (char**)args);\n"
    "Pattern: Use execv/execve with separate argument arrays, never system().\n\n"
    "REPAIR EXAMPLE 2:\n"
    "Before: popen((cmd + param).c_str(), \"r\");\n"
    "After:  // Whitelist validation before use\n"
    "        if (!isValidParam(param)) {{ return ERROR; }}\n"
    "        popen((cmd + param).c_str(), \"r\");\n"
    "Pattern: Whitelist-validate all user input before shell use.\n\n"
    "ANTI-PATTERNS TO AVOID:\n"
    "- Never use system() or popen() with user-controlled input\n"
    "- Blacklist filtering is insufficient - use whitelist only\n"
)

CWE78_REPAIR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_78_BODY)),
    ("user", "Vulnerable code (CWE-78):\n```\n{code}\n```\n\n"
             "Vulnerability report: {vulnerability_report}\n"
             "Vulnerable lines: {vulnerable_lines}"),
])


# ── 通用修复Prompt（CWE未知时使用）─────────────────────────────────────────────

_GENERIC_BODY = (
    "You are a security expert fixing a code vulnerability.\n\n"
    "Analyze the vulnerability report carefully and generate the minimal fix.\n"
    "Focus on eliminating the root cause without changing the function's semantics.\n\n"
    "GENERAL REPAIR PRINCIPLES:\n"
    "1. Fix the specific vulnerability, do not rewrite the entire function\n"
    "2. Add bounds checks, null checks, or synchronization as needed\n"
    "3. Prefer standard library safe functions over manual implementations\n"
    "4. Ensure the fix does not introduce new vulnerabilities\n"
)

GENERIC_REPAIR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_GENERIC_BODY)),
    ("user", "Vulnerable code ({cwe}):\n```\n{code}\n```\n\n"
             "Vulnerability report: {vulnerability_report}\n"
             "Vulnerable lines: {vulnerable_lines}"),
])


# ── Prompt 路由 ───────────────────────────────────────────────────────────────

REPAIR_PROMPTS = {
    "CWE-476": CWE476_REPAIR_PROMPT,
    "CWE-401": CWE401_REPAIR_PROMPT,
    "CWE-362": CWE362_REPAIR_PROMPT,
    "CWE-416": CWE416_REPAIR_PROMPT,
    "CWE-119": CWE119_REPAIR_PROMPT,
    "CWE-122": CWE119_REPAIR_PROMPT,  # 子类，用相同模板
    "CWE-190": CWE190_REPAIR_PROMPT,
    "CWE-134": CWE134_REPAIR_PROMPT,
    "CWE-78":  CWE78_REPAIR_PROMPT,
}


def get_repair_prompt(cwe_id: str) -> ChatPromptTemplate:
    """根据 CWE 类型返回对应的修复 Prompt。"""
    if not cwe_id:
        return GENERIC_REPAIR_PROMPT
    for key in REPAIR_PROMPTS:
        if key in str(cwe_id).upper():
            return REPAIR_PROMPTS[key]
    return GENERIC_REPAIR_PROMPT
