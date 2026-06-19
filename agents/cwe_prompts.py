# [C2: CWE专用Prompt] 9种CWE类型的专用检测模板，包含Few-Shot示例和Chain-of-Thought推理步骤
"""CWE-specific prompt templates with Few-Shot examples and Chain-of-Thought (CoT).

Key upgrades over v1:
1. FEW-SHOT: concrete vulnerable + safe code examples per CWE
2. CHAIN-OF-THOUGHT: step-by-step reasoning before verdict
   Step 1: Identify dangerous operations
   Step 2: Trace input source (attacker-controlled?)
   Step 3: Check defensive measures
   Step 4: Conclude

Note: code examples use {{ and }} to produce literal { and } in the rendered prompt.
"""

from langchain_core.prompts import ChatPromptTemplate

# ── shared blocks ──────────────────────────────────────────────────────────────

_COT = (
    "\n回答之前，请按步骤思考：\n"
    "1. 识别：存在哪些危险操作？\n"
    "2. 追踪：输入从哪里来？攻击者能控制吗？\n"
    "3. 检查：是否已有边界/空值/合法性检查？\n"
    "4. 结论：基于1-3，漏洞是否确认或排除？\n"
)

_FMT = (
    "\n只输出JSON，不要markdown代码块：\n"
    '{{\n'
    '  "has_vulnerability": true/false,\n'
    '  "vulnerability_type": "CWE-XXX: 名称" 或 null,\n'
    '  "reason": "2-3句话，引用具体代码证据",\n'
    '  "confidence": 0.0-1.0,\n'
    '  "vulnerable_lines": [{{"line_number": N, "code": "...", "explanation": "..."}}],\n'
    '  "cot_reasoning": "步骤分析的简要总结"\n'
    '}}\n'
)


def _sys(body: str) -> str:
    return body + _COT + "{context}\n" + _FMT


# ── CWE-119: Buffer Overflow ───────────────────────────────────────────────────

_119_BODY = (
    "你只检查 CWE-119（缓冲区溢出）。\n\n"
    "漏洞示例：\n"
    "```cpp\n"
    "void cb(const std_msgs::String::ConstPtr& msg) {{\n"
    "    char buf[64];\n"
    "    strcpy(buf, msg->data.c_str());  // 漏洞：没有长度检查\n"
    "}}\n"
    "```\n"
    "原因：strcpy复制无限字节；输入超过64字节会覆盖栈。\n\n"
    "安全示例：\n"
    "```cpp\n"
    "void cb(const std_msgs::String::ConstPtr& msg) {{\n"
    "    char buf[64];\n"
    "    strncpy(buf, msg->data.c_str(), sizeof(buf)-1);  // 安全：有边界限制\n"
    "}}\n"
    "```\n"
    "原因：strncpy将复制限制在缓冲区大小内。\n\n"
    "标记条件：不安全的复制函数 + 固定缓冲区 + 没有对来源长度的检查。\n"
    "不要标记：strncpy/snprintf、常量来源、或已有大小验证。\n\n"
    "参考案例（来自RAG知识库）：\n"
)

CWE_119_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_119_BODY)),
    ("user", "Code:\n{code}"),
])

# ── CWE-476: NULL Pointer Dereference ─────────────────────────────────────────

_476_BODY = (
    "你只检查 CWE-476（空指针解引用）。\n\n"
    "漏洞示例：\n"
    "```cpp\n"
    "void process(ros::NodeHandle* nh) {{\n"
    "    std::string v;\n"
    "    nh->getParam(\"speed\", v);  // 漏洞：nh可能为空\n"
    "}}\n"
    "```\n"
    "原因：没有空值检查；nh为nullptr时解引用会崩溃。\n\n"
    "安全示例：\n"
    "```cpp\n"
    "void process(ros::NodeHandle* nh) {{\n"
    "    if (!nh) return;               // 安全：空值保护\n"
    "    std::string v;\n"
    "    nh->getParam(\"speed\", v);\n"
    "}}\n"
    "```\n"
    "标记条件：指针/智能指针在没有前置空值检查的情况下被解引用。\n"
    "不要标记：所有路径上都有空值检查，或指针已值初始化。\n\n"
    "参考案例（来自RAG知识库）：\n"
)

CWE_476_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_476_BODY)),
    ("user", "Code:\n{code}"),
])

# ── CWE-401: Memory Leak ──────────────────────────────────────────────────────

_401_BODY = (
    "你只检查 CWE-401（内存泄漏）。\n\n"
    "漏洞示例：\n"
    "```cpp\n"
    "void process(const std::string& key) {{\n"
    "    char* buf = new char[256];      // 分配内存\n"
    "    if (key.empty()) return;        // 漏洞：提前返回，buf泄漏\n"
    "    strcpy(buf, key.c_str());\n"
    "    delete[] buf;\n"
    "}}\n"
    "```\n"
    "原因：key为空时提前返回，buf在该路径上泄漏。\n\n"
    "安全示例：\n"
    "```cpp\n"
    "void process(const std::string& key) {{\n"
    "    std::unique_ptr<char[]> buf(new char[256]);  // 安全：RAII\n"
    "    if (key.empty()) return;   // unique_ptr自动释放\n"
    "    strcpy(buf.get(), key.c_str());\n"
    "}}\n"
    "```\n"
    "标记条件：资源已分配 + 存在跳过释放的代码路径 + 没有RAII包装。\n"
    "不要标记：RAII（unique_ptr/shared_ptr），或所有路径都释放了资源。\n\n"
    "参考案例（来自RAG知识库）：\n"
)

CWE_401_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_401_BODY)),
    ("user", "Code:\n{code}"),
])

# ── CWE-362: Race Condition ────────────────────────────────────────────────────

_362_BODY = (
    "你只检查 CWE-362（竞态条件/数据竞争）。\n\n"
    "漏洞示例：\n"
    "```cpp\n"
    "int counter = 0;  // 共享变量\n"
    "void cb_a(const Msg::ConstPtr&) {{ counter++; }}       // 漏洞\n"
    "void cb_b(const Msg::ConstPtr&) {{ if (counter>10) reset(); }}  // 漏洞\n"
    "```\n"
    "原因：counter被并发回调访问，没有mutex保护。\n\n"
    "安全示例：\n"
    "```cpp\n"
    "std::atomic<int> counter{{0}};\n"
    "void cb_a(const Msg::ConstPtr&) {{ counter.fetch_add(1); }}  // 安全：原子操作\n"
    "```\n"
    "标记条件：共享可变变量 + 并发访问（线程/回调）+ 没有mutex/atomic/lock_guard。\n"
    "不要标记：局部变量、只读共享状态、或已正确加锁的访问。\n\n"
    "参考案例（来自RAG知识库）：\n"
)

CWE_362_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_362_BODY)),
    ("user", "Code:\n{code}"),
])

# ── CWE-416: Use After Free ────────────────────────────────────────────────────

_416_BODY = (
    "你只检查 CWE-416（释放后使用）。\n\n"
    "漏洞示例：\n"
    "```cpp\n"
    "void cleanup(Sensor* s) {{\n"
    "    delete s;         // 释放\n"
    "    s->shutdown();    // 漏洞：释放后使用\n"
    "}}\n"
    "```\n"
    "原因：s被删除后又被解引用。\n\n"
    "安全示例：\n"
    "```cpp\n"
    "void cleanup(Sensor* s) {{\n"
    "    s->shutdown();    // 先使用\n"
    "    delete s;         // 安全：最后一次使用后再释放\n"
    "    s = nullptr;\n"
    "}}\n"
    "```\n"
    "标记条件：指针被释放（delete/free）之后又被解引用。\n"
    "不要标记：使用严格在释放之前，或有明确所有权的智能指针。\n\n"
    "参考案例（来自RAG知识库）：\n"
)

CWE_416_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_416_BODY)),
    ("user", "Code:\n{code}"),
])

# ── CWE-190: Integer Overflow ─────────────────────────────────────────────────

_190_BODY = (
    "你只检查 CWE-190（整数溢出）。\n\n"
    "漏洞示例：\n"
    "```cpp\n"
    "void alloc(uint16_t count) {{\n"
    "    uint16_t total = count * sizeof(Item);  // 漏洞：可能溢出\n"
    "    Item* arr = (Item*)malloc(total);\n"
    "}}\n"
    "```\n"
    "原因：count过大会导致count*sizeof(Item)回绕为小值，分配的缓冲区不够大。\n\n"
    "安全示例：\n"
    "```cpp\n"
    "void alloc(uint16_t count) {{\n"
    "    if (count > MAX_ITEMS) return;           // 安全：边界检查\n"
    "    size_t total = (size_t)count * sizeof(Item);\n"
    "    Item* arr = (Item*)malloc(total);\n"
    "}}\n"
    "```\n"
    "标记条件：用户可控值的整数运算被用作大小/索引，且没有溢出检查。\n\n"
    "参考案例（来自RAG知识库）：\n"
)

CWE_190_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_190_BODY)),
    ("user", "代码：\n{code}"),
])

# ── CWE-134: Format String ────────────────────────────────────────────────────

_134_BODY = (
    "你只检查 CWE-134（格式化字符串漏洞）。\n\n"
    "漏洞示例：\n"
    "```cpp\n"
    "void log(const std::string& msg) {{\n"
    "    printf(msg.c_str());   // 漏洞：用户控制格式串\n"
    "}}\n"
    "```\n"
    "原因：攻击者传入\"%x%x\"可读取栈内容，传入\"%n\"可写入内存。\n\n"
    "安全示例：\n"
    "```cpp\n"
    "void log(const std::string& msg) {{\n"
    '    printf("%s", msg.c_str());  // 安全：使用字面量格式串\n'
    "}}\n"
    "```\n"
    "标记条件：printf/fprintf/sprintf/ROS_INFO的第一个（格式）参数是来自外部输入的变量。\n"
    '不要标记：第一个参数是字符串字面量，如"%s"或"value: %d"。\n\n'
    "参考案例（来自RAG知识库）：\n"
)

CWE_134_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_134_BODY)),
    ("user", "代码：\n{code}"),
])

# ── CWE-78: Command Injection ─────────────────────────────────────────────────

_78_BODY = (
    "你只检查 CWE-78（操作系统命令注入）。\n\n"
    "漏洞示例：\n"
    "```cpp\n"
    "void launch(const std::string& node) {{\n"
    "    std::string cmd = \"ros2 run \" + node;  // 漏洞：命令注入\n"
    "    system(cmd.c_str());\n"
    "}}\n"
    "```\n"
    "原因：攻击者传入\"x; rm -rf /\"作为node参数。\n\n"
    "安全示例：\n"
    "```cpp\n"
    "void launch(const std::string& node) {{\n"
    "    // 安全：execvp避免shell解析\n"
    "    execvp(\"ros2\", {{\"ros2\",\"run\",node.c_str(),nullptr}});\n"
    "}}\n"
    "```\n"
    "标记条件：system/popen/exec使用了包含外部输入的拼接字符串，且没有shell元字符过滤。\n\n"
    "参考案例（来自RAG知识库）：\n"
)

CWE_78_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_78_BODY)),
    ("user", "代码：\n{code}"),
])

# ── Generic fallback ──────────────────────────────────────────────────────────

_GENERIC_BODY = (
    "你是一位机器人代码安全专家，负责检测任意类型的漏洞。\n"
    "检查范围：CWE-119/476/401/362/416/190/134/78 或ROS特定问题。\n\n"
    "关键问题：攻击者可控的输入是否在没有充分验证的情况下到达了危险操作？\n\n"
    "参考案例（来自RAG知识库）：\n"
)

GENERIC_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_GENERIC_BODY)),
    ("user", "代码：\n{code}"),
])

# ── Registry ──────────────────────────────────────────────────────────────────

CWE_PROMPTS = {
    "CWE-119": CWE_119_PROMPT,
    "CWE-476": CWE_476_PROMPT,
    "CWE-401": CWE_401_PROMPT,
    "CWE-362": CWE_362_PROMPT,
    "CWE-416": CWE_416_PROMPT,
    "CWE-190": CWE_190_PROMPT,
    "CWE-134": CWE_134_PROMPT,
    "CWE-78":  CWE_78_PROMPT,
    "OTHER":   GENERIC_PROMPT,
}


def get_prompt_for_cwe(cwe: str):
    return CWE_PROMPTS.get(cwe, GENERIC_PROMPT)
