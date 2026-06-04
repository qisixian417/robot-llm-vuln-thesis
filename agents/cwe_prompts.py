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
    "\nBefore answering, think step by step:\n"
    "1. IDENTIFY: What dangerous operations exist?\n"
    "2. TRACE: Where does the input come from? Is it attacker-controllable?\n"
    "3. DEFEND: Are there existing bounds/null/sanity checks?\n"
    "4. CONCLUDE: Based on 1-3, is the vulnerability confirmed or ruled out?\n"
)

_FMT = (
    "\nOutput JSON only (no markdown fences):\n"
    '{{\n'
    '  "has_vulnerability": true/false,\n'
    '  "vulnerability_type": "CWE-XXX: name" or null,\n'
    '  "reason": "2-3 sentences citing specific code evidence",\n'
    '  "confidence": 0.0-1.0,\n'
    '  "vulnerable_lines": [{{"line_number": N, "code": "...", "explanation": "..."}}],\n'
    '  "cot_reasoning": "brief summary of your step-by-step analysis"\n'
    '}}\n'
)


def _sys(body: str) -> str:
    return body + _COT + "{context}\n" + _FMT


# ── CWE-119: Buffer Overflow ───────────────────────────────────────────────────

_119_BODY = (
    "You are checking ONLY for CWE-119 (Buffer Overflow).\n\n"
    "VULNERABLE EXAMPLE:\n"
    "```cpp\n"
    "void cb(const std_msgs::String::ConstPtr& msg) {{\n"
    "    char buf[64];\n"
    "    strcpy(buf, msg->data.c_str());  // VULNERABLE: no length check\n"
    "}}\n"
    "```\n"
    "Reason: strcpy copies unlimited bytes; input > 64 bytes overwrites stack.\n\n"
    "SAFE EXAMPLE:\n"
    "```cpp\n"
    "void cb(const std_msgs::String::ConstPtr& msg) {{\n"
    "    char buf[64];\n"
    "    strncpy(buf, msg->data.c_str(), sizeof(buf)-1);  // SAFE: bounded\n"
    "}}\n"
    "```\n"
    "Reason: strncpy limits copy to buffer size.\n\n"
    "FLAG only if: unsafe copy function + fixed buffer + NO length check on source.\n"
    "DO NOT flag: strncpy/snprintf, constant sources, or existing size validation.\n\n"
    "Reference cases (from RAG):\n"
)

CWE_119_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_119_BODY)),
    ("user", "Code:\n{code}"),
])

# ── CWE-476: NULL Pointer Dereference ─────────────────────────────────────────

_476_BODY = (
    "You are checking ONLY for CWE-476 (NULL Pointer Dereference).\n\n"
    "VULNERABLE EXAMPLE:\n"
    "```cpp\n"
    "void process(ros::NodeHandle* nh) {{\n"
    "    std::string v;\n"
    "    nh->getParam(\"speed\", v);  // VULNERABLE: nh may be null\n"
    "}}\n"
    "```\n"
    "Reason: no null check; dereference crashes if nh is nullptr.\n\n"
    "SAFE EXAMPLE:\n"
    "```cpp\n"
    "void process(ros::NodeHandle* nh) {{\n"
    "    if (!nh) return;               // SAFE: null guard\n"
    "    std::string v;\n"
    "    nh->getParam(\"speed\", v);\n"
    "}}\n"
    "```\n"
    "FLAG only if: pointer/smart_ptr dereferenced WITHOUT a preceding null check.\n"
    "DO NOT flag: if null check exists on ALL paths, or pointer is value-initialized.\n\n"
    "Reference cases (from RAG):\n"
)

CWE_476_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_476_BODY)),
    ("user", "Code:\n{code}"),
])

# ── CWE-401: Memory Leak ──────────────────────────────────────────────────────

_401_BODY = (
    "You are checking ONLY for CWE-401 (Memory Leak).\n\n"
    "VULNERABLE EXAMPLE:\n"
    "```cpp\n"
    "void process(const std::string& key) {{\n"
    "    char* buf = new char[256];      // allocate\n"
    "    if (key.empty()) return;        // VULNERABLE: early return, buf leaked\n"
    "    strcpy(buf, key.c_str());\n"
    "    delete[] buf;\n"
    "}}\n"
    "```\n"
    "Reason: early return leaks buf on the empty-key path.\n\n"
    "SAFE EXAMPLE:\n"
    "```cpp\n"
    "void process(const std::string& key) {{\n"
    "    std::unique_ptr<char[]> buf(new char[256]);  // SAFE: RAII\n"
    "    if (key.empty()) return;   // auto-freed by unique_ptr\n"
    "    strcpy(buf.get(), key.c_str());\n"
    "}}\n"
    "```\n"
    "FLAG only if: resource allocated + code path exists that skips deallocation "
    "+ no RAII wrapper.\n"
    "DO NOT flag: RAII (unique_ptr/shared_ptr), or all paths free the resource.\n\n"
    "Reference cases (from RAG):\n"
)

CWE_401_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_401_BODY)),
    ("user", "Code:\n{code}"),
])

# ── CWE-362: Race Condition ────────────────────────────────────────────────────

_362_BODY = (
    "You are checking ONLY for CWE-362 (Race Condition / Data Race).\n\n"
    "VULNERABLE EXAMPLE:\n"
    "```cpp\n"
    "int counter = 0;  // shared\n"
    "void cb_a(const Msg::ConstPtr&) {{ counter++; }}       // VULNERABLE\n"
    "void cb_b(const Msg::ConstPtr&) {{ if (counter>10) reset(); }}  // VULNERABLE\n"
    "```\n"
    "Reason: counter accessed by concurrent callbacks without mutex.\n\n"
    "SAFE EXAMPLE:\n"
    "```cpp\n"
    "std::atomic<int> counter{{0}};\n"
    "void cb_a(const Msg::ConstPtr&) {{ counter.fetch_add(1); }}  // SAFE: atomic\n"
    "```\n"
    "FLAG only if: shared mutable variable + concurrent access (threads/callbacks) "
    "+ no mutex/atomic/lock_guard.\n"
    "DO NOT flag: local variables, read-only shared state, or properly locked access.\n\n"
    "Reference cases (from RAG):\n"
)

CWE_362_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_362_BODY)),
    ("user", "Code:\n{code}"),
])

# ── CWE-416: Use After Free ────────────────────────────────────────────────────

_416_BODY = (
    "You are checking ONLY for CWE-416 (Use After Free).\n\n"
    "VULNERABLE EXAMPLE:\n"
    "```cpp\n"
    "void cleanup(Sensor* s) {{\n"
    "    delete s;         // free\n"
    "    s->shutdown();    // VULNERABLE: use after free\n"
    "}}\n"
    "```\n"
    "Reason: s is deleted then dereferenced.\n\n"
    "SAFE EXAMPLE:\n"
    "```cpp\n"
    "void cleanup(Sensor* s) {{\n"
    "    s->shutdown();    // use first\n"
    "    delete s;         // SAFE: free after last use\n"
    "    s = nullptr;\n"
    "}}\n"
    "```\n"
    "FLAG only if: pointer freed (delete/free) AND subsequently dereferenced.\n"
    "DO NOT flag: use strictly precedes free, smart pointer with clear ownership.\n\n"
    "Reference cases (from RAG):\n"
)

CWE_416_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_416_BODY)),
    ("user", "Code:\n{code}"),
])

# ── CWE-190: Integer Overflow ─────────────────────────────────────────────────

_190_BODY = (
    "You are checking ONLY for CWE-190 (Integer Overflow).\n\n"
    "VULNERABLE EXAMPLE:\n"
    "```cpp\n"
    "void alloc(uint16_t count) {{\n"
    "    uint16_t total = count * sizeof(Item);  // VULNERABLE: may overflow\n"
    "    Item* arr = (Item*)malloc(total);\n"
    "}}\n"
    "```\n"
    "Reason: large count causes count*sizeof(Item) to wrap to a small value; "
    "under-allocated buffer.\n\n"
    "SAFE EXAMPLE:\n"
    "```cpp\n"
    "void alloc(uint16_t count) {{\n"
    "    if (count > MAX_ITEMS) return;           // SAFE: bounds check\n"
    "    size_t total = (size_t)count * sizeof(Item);\n"
    "    Item* arr = (Item*)malloc(total);\n"
    "}}\n"
    "```\n"
    "FLAG only if: integer arithmetic on user-controlled value used as size/index "
    "+ no overflow check.\n\n"
    "Reference cases (from RAG):\n"
)

CWE_190_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_190_BODY)),
    ("user", "Code:\n{code}"),
])

# ── CWE-134: Format String ────────────────────────────────────────────────────

_134_BODY = (
    "You are checking ONLY for CWE-134 (Format String Vulnerability).\n\n"
    "VULNERABLE EXAMPLE:\n"
    "```cpp\n"
    "void log(const std::string& msg) {{\n"
    "    printf(msg.c_str());   // VULNERABLE: user controls format string\n"
    "}}\n"
    "```\n"
    "Reason: attacker passes \"%x%x\" to read stack, or \"%n\" to write memory.\n\n"
    "SAFE EXAMPLE:\n"
    "```cpp\n"
    "void log(const std::string& msg) {{\n"
    '    printf("%s", msg.c_str());  // SAFE: literal format string\n'
    "}}\n"
    "```\n"
    "FLAG only if: printf/fprintf/sprintf/ROS_INFO called with VARIABLE as first "
    "(format) argument from external input.\n"
    'DO NOT flag: first argument is a string literal like "%s" or "value: %d".\n\n'
    "Reference cases (from RAG):\n"
)

CWE_134_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_134_BODY)),
    ("user", "Code:\n{code}"),
])

# ── CWE-78: Command Injection ─────────────────────────────────────────────────

_78_BODY = (
    "You are checking ONLY for CWE-78 (OS Command Injection).\n\n"
    "VULNERABLE EXAMPLE:\n"
    "```cpp\n"
    "void launch(const std::string& node) {{\n"
    "    std::string cmd = \"ros2 run \" + node;  // VULNERABLE: injection\n"
    "    system(cmd.c_str());\n"
    "}}\n"
    "```\n"
    "Reason: attacker passes \"x; rm -rf /\" as node.\n\n"
    "SAFE EXAMPLE:\n"
    "```cpp\n"
    "void launch(const std::string& node) {{\n"
    "    // SAFE: execvp avoids shell interpretation\n"
    "    execvp(\"ros2\", {{\"ros2\",\"run\",node.c_str(),nullptr}});\n"
    "}}\n"
    "```\n"
    "FLAG only if: system/popen/exec called with concatenated string containing "
    "external input + no shell-metachar sanitization.\n\n"
    "Reference cases (from RAG):\n"
)

CWE_78_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_78_BODY)),
    ("user", "Code:\n{code}"),
])

# ── Generic fallback ──────────────────────────────────────────────────────────

_GENERIC_BODY = (
    "You are a robotics code security expert. Detect any vulnerability.\n"
    "Check for: CWE-119/476/401/362/416/190/134/78 or ROS-specific issues.\n\n"
    "Key question: Is attacker-controllable input reaching a dangerous operation "
    "without adequate validation?\n\n"
    "Reference cases (from RAG):\n"
)

GENERIC_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _sys(_GENERIC_BODY)),
    ("user", "Code:\n{code}"),
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
