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
    "\n生成修复代码前，请按步骤思考：\n"
    "1. 根因：漏洞的根本原因是什么？\n"
    "2. 策略：最小化修复方案是什么？（参考历史修复模式）\n"
    "3. 生成：编写修复代码，尽量少改几行\n"
    "4. 验证：修复是否消除了根因，且没有引入新问题？\n"
)

_REPAIR_FMT = (
    "\n你必须只输出合法的JSON，不要markdown代码块，JSON外不要有任何解释。\n"
    "以{{开头，以}}结尾。\n"
    "示例格式：\n"
    '{{"fixed_code": "void foo() {{\\n  // 修复后的代码\\n}}", '
    '"changes": [{{"line": 5, "original": "有问题的代码", "fixed": "修复后的代码", "reason": "原因"}}], '
    '"fix_strategy": "一句话描述修复策略", '
    '"confidence": 0.8, '
    '"cot_reasoning": "简要推理过程", '
    '"potential_issues": null}}\n'
)


def _sys(body: str) -> str:
    return body + _REPAIR_COT + "{rag_context}\n" + _REPAIR_FMT


# ── CWE-476: Null Pointer Dereference ────────────────────────────────────────

_476_BODY = (
    "你是一位安全专家，负责修复 CWE-476（空指针解引用）。\n\n"
    "修复示例1：\n"
    "修复前：node->value = 42;  // 没有空值检查\n"
    "修复后：if (node != nullptr) {{ node->value = 42; }}\n"
    "模式：在每次指针解引用前加空值检查。\n\n"
    "修复示例2：\n"
    "修复前：return ptr->data.c_str();\n"
    "修复后：if (!ptr) {{ return \"\"; }}\n"
    "        return ptr->data.c_str();\n"
    "模式：指针为空时提前返回或抛出异常。\n\n"
    "禁止的做法：\n"
    "- 不要使用 assert()，release版本中会被禁用\n"
    "- 不要静默忽略空指针，要返回错误或抛出异常\n"
)

CWE476_REPAIR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_476_BODY)),
    ("user", "有漏洞的代码（CWE-476）：\n```\n{code}\n```\n\n"
             "漏洞报告：{vulnerability_report}\n"
             "漏洞行：{vulnerable_lines}"),
])


# ── CWE-401: Memory Leak ──────────────────────────────────────────────────────

_401_BODY = (
    "你是一位安全专家，负责修复 CWE-401（内存泄漏）。\n\n"
    "修复示例1：\n"
    "修复前：char* buf = new char[size]; process(buf);  // 没有delete\n"
    "修复后：char* buf = new char[size]; process(buf); delete[] buf;\n"
    "模式：确保每次分配都有对应的释放。\n\n"
    "修复示例2（推荐RAII）：\n"
    "修复前：Node* n = new Node(); return n->value;\n"
    "修复后：auto n = std::make_unique<Node>(); return n->value;\n"
    "模式：使用智能指针（unique_ptr/shared_ptr）自动管理内存。\n\n"
    "禁止的做法：\n"
    "- 不要只在if/else的某一个分支加delete\n"
    "- C++中推荐用std::unique_ptr代替原始new/delete\n"
)

CWE401_REPAIR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_401_BODY)),
    ("user", "有漏洞的代码（CWE-401）：\n```\n{code}\n```\n\n"
             "漏洞报告：{vulnerability_report}\n"
             "漏洞行：{vulnerable_lines}"),
])


# ── CWE-362: Race Condition ───────────────────────────────────────────────────

_362_BODY = (
    "你是一位安全专家，负责修复 CWE-362（竞态条件）。\n\n"
    "修复示例1：\n"
    "修复前：shared_counter++;  // 未保护的共享变量\n"
    "修复后：std::lock_guard<std::mutex> lock(mtx); shared_counter++;\n"
    "模式：用mutex保护所有共享变量的访问。\n\n"
    "修复示例2：\n"
    "修复前：if (data_ready) {{ process(data); }}\n"
    "修复后：std::unique_lock<std::mutex> lock(mtx);\n"
    "        cv.wait(lock, []{{ return data_ready; }});\n"
    "        process(data);\n"
    "模式：使用条件变量进行线程同步。\n\n"
    "禁止的做法：\n"
    "- 不要用volatile替代mutex\n"
    "- 不要假设操作是原子的，除非使用std::atomic\n"
)

CWE362_REPAIR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_362_BODY)),
    ("user", "有漏洞的代码（CWE-362）：\n```\n{code}\n```\n\n"
             "漏洞报告：{vulnerability_report}\n"
             "漏洞行：{vulnerable_lines}"),
])


# ── CWE-416: Use After Free ───────────────────────────────────────────────────

_416_BODY = (
    "你是一位安全专家，负责修复 CWE-416（释放后使用）。\n\n"
    "修复示例1：\n"
    "修复前：delete ptr; ptr->method();  // 释放后使用\n"
    "修复后：delete ptr; ptr = nullptr;  // 释放后置空\n"
    "模式：delete后立即将指针设为nullptr。\n\n"
    "修复示例2：\n"
    "修复前：free(buf); return buf[0];  // 释放后使用\n"
    "修复后：char result = buf[0]; free(buf); return result;\n"
    "模式：在释放内存之前先提取需要的值。\n\n"
    "禁止的做法：\n"
    "- 释放后永远不要访问内存，即使是'清理'操作\n"
    "- 推荐用std::unique_ptr彻底避免手动free\n"
)

CWE416_REPAIR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_416_BODY)),
    ("user", "有漏洞的代码（CWE-416）：\n```\n{code}\n```\n\n"
             "漏洞报告：{vulnerability_report}\n"
             "漏洞行：{vulnerable_lines}"),
])


# ── CWE-119: Buffer Overflow ──────────────────────────────────────────────────

_119_BODY = (
    "你是一位安全专家，负责修复 CWE-119（缓冲区溢出）。\n\n"
    "修复示例1：\n"
    "修复前：strcpy(buf, input);  // 没有长度检查\n"
    "修复后：strncpy(buf, input, sizeof(buf)-1); buf[sizeof(buf)-1] = '\\0';\n"
    "模式：用有界函数替换不安全的字符串函数。\n\n"
    "修复示例2：\n"
    "修复前：memcpy(dst, src, user_len);  // 用户可控的长度\n"
    "修复后：size_t safe_len = std::min(user_len, sizeof(dst));\n"
    "        memcpy(dst, src, safe_len);\n"
    "模式：使用前验证并限制用户可控的大小。\n\n"
    "禁止的做法：\n"
    "- strncpy不保证null结尾，必须手动添加\n"
    "- 不要使用sprintf，改用snprintf\n"
)

CWE119_REPAIR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_119_BODY)),
    ("user", "有漏洞的代码（CWE-119）：\n```\n{code}\n```\n\n"
             "漏洞报告：{vulnerability_report}\n"
             "漏洞行：{vulnerable_lines}"),
])


# ── CWE-190: Integer Overflow ─────────────────────────────────────────────────

_190_BODY = (
    "你是一位安全专家，负责修复 CWE-190（整数溢出）。\n\n"
    "修复示例1：\n"
    "修复前：int size = a + b; char* buf = new char[size];\n"
    "修复后：if (a > INT_MAX - b) {{ throw std::overflow_error(\"溢出\"); }}\n"
    "        int size = a + b; char* buf = new char[size];\n"
    "模式：算术运算前检查是否会溢出。\n\n"
    "修复示例2：\n"
    "修复前：uint32_t len = data_len * item_size;\n"
    "修复后：if (item_size != 0 && data_len > UINT32_MAX / item_size)\n"
    "            return ERROR;\n"
    "        uint32_t len = data_len * item_size;\n"
    "模式：乘法运算前验证不会溢出。\n\n"
    "禁止的做法：\n"
    "- 不要在溢出已经发生后才转换为更大的类型\n"
    "- 大小应使用size_t，不要用int\n"
)

CWE190_REPAIR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_190_BODY)),
    ("user", "有漏洞的代码（CWE-190）：\n```\n{code}\n```\n\n"
             "漏洞报告：{vulnerability_report}\n"
             "漏洞行：{vulnerable_lines}"),
])


# ── CWE-134: Format String ────────────────────────────────────────────────────

_134_BODY = (
    "你是一位安全专家，负责修复 CWE-134（格式化字符串）。\n\n"
    "修复示例1：\n"
    "修复前：printf(user_input);  // 用户控制格式串\n"
    "修复后：printf(\"%s\", user_input);  // 固定格式串\n"
    "模式：始终使用字面量格式串，永远不要使用用户可控的格式串。\n\n"
    "修复示例2：\n"
    "修复前：fprintf(log, msg);  // 用户可控的msg作为格式串\n"
    "修复后：fprintf(log, \"%s\", msg);  // msg只作为数据\n"
    "模式：用户输入作为参数传入，而不是格式串。\n\n"
    "禁止的做法：\n"
    "- 永远不要把用户可控字符串作为printf系列函数的格式参数\n"
    "- 这同样适用于sprintf、fprintf、snprintf、syslog等\n"
)

CWE134_REPAIR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_134_BODY)),
    ("user", "有漏洞的代码（CWE-134）：\n```\n{code}\n```\n\n"
             "漏洞报告：{vulnerability_report}\n"
             "漏洞行：{vulnerable_lines}"),
])


# ── CWE-78: Command Injection ─────────────────────────────────────────────────

_78_BODY = (
    "你是一位安全专家，负责修复 CWE-78（命令注入）。\n\n"
    "修复示例1：\n"
    "修复前：system((\"ls \" + user_input).c_str());\n"
    "修复后：// 用execv加参数数组代替system()\n"
    "        const char* args[] = {{\"ls\", user_input.c_str(), nullptr}};\n"
    "        execv(\"/bin/ls\", (char**)args);\n"
    "模式：用execv/execve加独立参数数组，永远不要用system()。\n\n"
    "修复示例2：\n"
    "修复前：popen((cmd + param).c_str(), \"r\");\n"
    "修复后：// 使用前做白名单验证\n"
    "        if (!isValidParam(param)) {{ return ERROR; }}\n"
    "        popen((cmd + param).c_str(), \"r\");\n"
    "模式：所有用户输入在用于shell之前做白名单验证。\n\n"
    "禁止的做法：\n"
    "- 永远不要将用户可控输入用于system()或popen()\n"
    "- 黑名单过滤不够，只用白名单\n"
)

CWE78_REPAIR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_78_BODY)),
    ("user", "有漏洞的代码（CWE-78）：\n```\n{code}\n```\n\n"
             "漏洞报告：{vulnerability_report}\n"
             "漏洞行：{vulnerable_lines}"),
])


# ── 通用修复Prompt（CWE未知时使用）─────────────────────────────────────────────

_GENERIC_BODY = (
    "你是一位安全专家，负责修复代码漏洞。\n\n"
    "仔细分析漏洞报告并生成最小化修复。\n"
    "重点消除根因，不改变函数的语义。\n\n"
    "通用修复原则：\n"
    "1. 只修复具体的漏洞，不要重写整个函数\n"
    "2. 根据需要添加边界检查、空值检查或同步机制\n"
    "3. 优先使用标准库的安全函数，而不是手动实现\n"
    "4. 确保修复不会引入新漏洞\n"
)

GENERIC_REPAIR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_GENERIC_BODY)),
    ("user", "有漏洞的代码（{cwe}）：\n```\n{code}\n```\n\n"
             "漏洞报告：{vulnerability_report}\n"
             "漏洞行：{vulnerable_lines}"),
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
