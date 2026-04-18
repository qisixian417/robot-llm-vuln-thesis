#!/usr/bin/env python3
"""
RoboGuard 数据集构建：从 GitHub 爬取真实机器人代码漏洞数据
支持断点续爬、多策略搜索、函数级代码提取

运行方式：
  cd robot-llm-vuln-thesis
  python scripts/crawl_github_dataset.py

必需环境变量：
  GITHUB_TOKEN=ghp_xxxx   （5000次/h，无 token 仅 60次/h）

输出：
  data/dataset_full.jsonl       微调数据集
  data/rag_corpus_full.jsonl    RAG 语料库
"""

import base64
import hashlib
import json
import os
import re
import sys
import time
import random
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote

if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from dotenv import load_dotenv
import urllib.request

load_dotenv()

# ─────────────────────────────────────────────
# 配置
# ─────────────────────────────────────────────
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
TARGET_TOTAL = 1000
VULN_RATIO = 0.5
MAX_CODE_LEN = 2000
MIN_CODE_LEN = 40
REQUEST_DELAY = 2.5 if GITHUB_TOKEN else 6.0
SEARCH_DELAY = 3.0  # GitHub search API 更严格
OUTPUT_PATH = Path("data/dataset_full.jsonl")
RAG_OUTPUT_PATH = Path("data/rag_corpus_full.jsonl")
PROGRESS_PATH = Path("data/.crawl_progress.json")
# ── 机器人相关仓库 ──────────────────────────
ROBOTICS_REPOS = [
    # ROS 核心
    "ros/ros_comm", "ros/roscpp_core", "ros/ros", "ros/actionlib",
    "ros2/rclcpp", "ros2/rclpy", "ros2/rcl", "ros2/rmw",
    "ros2/rosidl", "ros2/rcutils", "ros2/geometry2",
    # 规划与导航
    "ros-planning/moveit", "ros-planning/moveit2",
    "ros-planning/navigation2", "ros-planning/navigation",
    # 仿真
    "gazebosim/gz-sim", "gazebosim/gz-transport",
    "ros-simulation/gazebo_ros_pkgs",
    # 感知
    "ros-perception/image_pipeline", "ros-perception/perception_pcl",
    "ros-perception/vision_opencv",
    # 无人机
    "PX4/PX4-Autopilot", "ArduPilot/ardupilot",
    "mavlink/mavlink", "mavlink/mavros",
    # 控制
    "ros-controls/ros2_control", "ros-controls/control_toolbox",
    "ros-controls/ros_controllers",
    # SLAM
    "cartographer-project/cartographer", "cartographer-project/cartographer_ros",
    "SteveMacenski/slam_toolbox",
    # 自动驾驶与通用机器人
    "autowarefoundation/autoware", "commaai/openpilot",
    "ApolloAuto/apollo", "carla-simulator/carla",
    "RobotWebTools/rosbridge_suite", "ros-visualization/rviz",
    "micro-ROS/micro_ros_setup", "eProsima/Fast-DDS",
]

# ── CWE 映射 ──────────────────────────────
CWE_MAP = {
    "CWE-119": ("Buffer Overflow", "HIGH",
                 ["memcpy(", "strcpy(", "strcat(", "sprintf(", "gets("]),
    "CWE-78":  ("OS Command Injection", "CRITICAL",
                 ["system(", "popen(", "os.system(", "subprocess.call(", "exec("]),
    "CWE-89":  ("SQL Injection", "HIGH",
                 ["execute(", "cursor.execute(", "raw_input"]),
    "CWE-416": ("Use After Free", "HIGH",
                 ["free(", "delete ", "delete[]"]),
    "CWE-190": ("Integer Overflow", "MEDIUM",
                 ["INT_MAX", "UINT_MAX", "overflow"]),
    "CWE-362": ("Race Condition", "MEDIUM",
                 ["pthread_mutex", "std::mutex", "lock(", "threading.Lock"]),
    "CWE-401": ("Memory Leak", "MEDIUM",
                 ["malloc(", "new ", "calloc(", "realloc("]),
    "CWE-125": ("Out-of-bounds Read", "HIGH",
                 ["buffer[", "array[", "memcmp("]),
    "CWE-134": ("Format String", "HIGH",
                 ["printf(", "fprintf(", "sprintf(", "syslog("]),
    "CWE-369": ("Divide By Zero", "MEDIUM",
                 ["/ 0", "/0", "divide", "division"]),
    "CWE-367": ("TOCTOU Race Condition", "MEDIUM",
                 ["access(", "stat(", "open("]),
}

# ── 搜索关键词 ──────────────────────────────
VULN_SEARCH_TERMS = [
    "fix vulnerability", "fix buffer overflow", "fix injection",
    "fix use after free", "fix memory leak", "fix race condition",
    "CVE", "security fix", "fix crash", "fix segfault",
    "fix null pointer", "fix overflow", "fix out of bounds",
]

SAFE_PATTERNS_CPP = [
    "std::unique_ptr", "std::shared_ptr", "std::lock_guard",
    "std::make_shared", "std::make_unique", "RAII",
]
SAFE_PATTERNS_PY = [
    "isinstance(", "try:", "with open(", "logging.getLogger",
]

# ─────────────────────────────────────────────
# GitHub API 封装
# ─────────────────────────────────────────────
class GitHubAPI:
    def __init__(self, token: str):
        self.token = token
        self.call_count = 0
        self.last_call = 0.0

    def _request(self, url: str, accept: str = "application/vnd.github+json",
                 delay: float = REQUEST_DELAY, retries: int = 3) -> Optional[Any]:
        for attempt in range(retries):
            elapsed = time.time() - self.last_call
            if elapsed < delay:
                time.sleep(delay - elapsed)
            req = urllib.request.Request(url)
            req.add_header("Accept", accept)
            req.add_header("User-Agent", "RoboGuard-Crawler/1.0")
            if self.token:
                req.add_header("Authorization", f"token {self.token}")
            try:
                self.last_call = time.time()
                self.call_count += 1
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except HTTPError as e:
                if e.code == 403:
                    reset = e.headers.get("X-RateLimit-Reset")
                    if reset:
                        wait = max(int(reset) - int(time.time()), 10)
                        print(f"  [rate-limit] 等待 {wait}s ...")
                        time.sleep(wait + 1)
                        continue
                    time.sleep(60)
                    continue
                elif e.code == 422 or e.code == 404:
                    return None
                elif e.code == 502 or e.code == 503:
                    time.sleep(5 * (attempt + 1))
                    continue
                else:
                    print(f"  [HTTP {e.code}] {url[:80]}")
                    return None
            except (URLError, TimeoutError):
                time.sleep(5 * (attempt + 1))
                continue
        return None

    def search_commits(self, query: str, page: int = 1) -> Optional[dict]:
        q = quote(query, safe="")
        url = f"https://api.github.com/search/commits?q={q}&per_page=30&page={page}"
        return self._request(url, accept="application/vnd.github.cloak-preview+json",
                             delay=SEARCH_DELAY)

    def search_code(self, query: str, page: int = 1) -> Optional[dict]:
        q = quote(query, safe="")
        url = f"https://api.github.com/search/code?q={q}&per_page=30&page={page}"
        return self._request(url, delay=SEARCH_DELAY)

    def get_file_content(self, owner: str, repo: str, path: str,
                         ref: str = "") -> Optional[str]:
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{quote(path, safe='/')}"
        if ref:
            url += f"?ref={ref}"
        data = self._request(url)
        if data and "content" in data:
            try:
                return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            except Exception:
                return None
        return None

    def get_commit(self, owner: str, repo: str, sha: str) -> Optional[dict]:
        url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
        return self._request(url)

    def list_repo_files(self, owner: str, repo: str, path: str = "",
                        ref: str = "") -> Optional[list]:
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{quote(path, safe='/')}"
        if ref:
            url += f"?ref={ref}"
        return self._request(url)

# ─────────────────────────────────────────────
# 进度管理
# ─────────────────────────────────────────────
class ProgressManager:
    def __init__(self, path: Path):
        self.path = path
        self.seen_ids: set = set()
        self.seen_hashes: set = set()
        self.counts = {"label_0": 0, "label_1": 0}
        self.cursors: Dict[str, Any] = {}
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self.seen_ids = set(data.get("seen_ids", []))
                self.seen_hashes = set(data.get("seen_hashes", []))
                self.counts = data.get("counts", self.counts)
                self.cursors = data.get("cursors", {})
                print(f"[resume] 已有 {self.counts} 条记录，{len(self.seen_ids)} 个ID")
            except Exception:
                pass

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({
            "seen_ids": list(self.seen_ids),
            "seen_hashes": list(self.seen_hashes),
            "counts": self.counts,
            "cursors": self.cursors,
        }, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)

    def is_dup(self, record_id: str, code: str) -> bool:
        code_hash = hashlib.md5(re.sub(r"\s+", "", code).encode()).hexdigest()
        return record_id in self.seen_ids or code_hash in self.seen_hashes

    def mark(self, record_id: str, code: str, label: int):
        code_hash = hashlib.md5(re.sub(r"\s+", "", code).encode()).hexdigest()
        self.seen_ids.add(record_id)
        self.seen_hashes.add(code_hash)
        self.counts[f"label_{label}"] += 1

# ─────────────────────────────────────────────
# 代码提取工具
# ─────────────────────────────────────────────
def extract_function_cpp(source: str, match_pos: int) -> Optional[str]:
    """从 C++ 源码中提取包含 match_pos 的完整函数。"""
    lines = source.split("\n")
    # 找到 match_pos 所在行号
    char_count = 0
    target_line = 0
    for i, line in enumerate(lines):
        char_count += len(line) + 1
        if char_count > match_pos:
            target_line = i
            break
    # 向上找函数头
    func_start = target_line
    for i in range(target_line, max(target_line - 50, -1), -1):
        line = lines[i].strip()
        if re.match(r"^[\w\s\*&:<>,]+\w+\s*\(", line) and "{" in "".join(lines[i:i+3]):
            func_start = i
            break
    # 向下找匹配的 }
    brace_count = 0
    func_end = target_line
    started = False
    for i in range(func_start, min(len(lines), func_start + 100)):
        for ch in lines[i]:
            if ch == "{":
                brace_count += 1
                started = True
            elif ch == "}":
                brace_count -= 1
        if started and brace_count <= 0:
            func_end = i
            break
    snippet = "\n".join(lines[func_start:func_end + 1])
    if MIN_CODE_LEN <= len(snippet) <= MAX_CODE_LEN:
        return snippet
    return None


def extract_function_python(source: str, match_pos: int) -> Optional[str]:
    """从 Python 源码中提取包含 match_pos 的完整函数。"""
    lines = source.split("\n")
    char_count = 0
    target_line = 0
    for i, line in enumerate(lines):
        char_count += len(line) + 1
        if char_count > match_pos:
            target_line = i
            break
    # 向上找 def
    func_start = target_line
    for i in range(target_line, max(target_line - 50, -1), -1):
        if re.match(r"^\s*def\s+\w+", lines[i]):
            func_start = i
            break
    # 向下找函数结束（下一个同级 def/class 或缩进减少）
    if func_start < len(lines):
        base_indent = len(lines[func_start]) - len(lines[func_start].lstrip())
    else:
        return None
    func_end = min(len(lines) - 1, func_start + 80)
    for i in range(func_start + 1, min(len(lines), func_start + 80)):
        stripped = lines[i].strip()
        if not stripped:
            continue
        indent = len(lines[i]) - len(lines[i].lstrip())
        if indent <= base_indent and stripped and not stripped.startswith("#"):
            func_end = i - 1
            break
    snippet = "\n".join(lines[func_start:func_end + 1])
    if MIN_CODE_LEN <= len(snippet) <= MAX_CODE_LEN:
        return snippet
    return None


def extract_diff_removed(patch: str) -> str:
    """从 git diff patch 中提取被删除的行（漏洞代码）。"""
    removed = []
    for line in patch.split("\n"):
        if line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:])
    return "\n".join(removed)


def classify_cwe(code: str, message: str = "") -> Optional[Tuple[str, str, str]]:
    """根据代码和 commit message 推断 CWE 类型。"""
    text = (code + " " + message).lower()
    scores: Dict[str, int] = {}
    for cwe_id, (name, severity, patterns) in CWE_MAP.items():
        score = 0
        for p in patterns:
            if p.lower() in text:
                score += 1
        if cwe_id.lower().replace("-", "") in text.replace("-", ""):
            score += 3
        if name.lower().replace(" ", "") in text.replace(" ", ""):
            score += 2
        if score > 0:
            scores[cwe_id] = score
    if scores:
        best = max(scores, key=scores.get)
        name, severity, _ = CWE_MAP[best]
        return best, name, severity
    return None


def make_id(repo: str, cwe_id: str, code: str) -> str:
    slug = repo.replace("/", "_")
    h = hashlib.md5(code.encode("utf-8", errors="replace")).hexdigest()[:8]
    return f"{slug}_{cwe_id or 'benign'}_{h}"


def detect_language(path: str) -> Optional[str]:
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    if ext in ("cpp", "cc", "cxx", "c", "h", "hpp", "hxx"):
        return "C++"
    elif ext == "py":
        return "Python"
    return None

# ─────────────────────────────────────────────
# 策略 A：安全修复 Commit
# ─────────────────────────────────────────────
def strategy_security_commits(api: GitHubAPI, progress: ProgressManager) -> Iterator[dict]:
    """搜索机器人仓库中的安全修复 commit，提取修复前的漏洞代码。"""
    for repo in ROBOTICS_REPOS:
        owner, name = repo.split("/")
        for term in VULN_SEARCH_TERMS:
            cursor_key = f"commits_{repo}_{term}"
            start_page = progress.cursors.get(cursor_key, 1)
            for page in range(start_page, 4):  # 最多 3 页
                query = f"repo:{repo} {term}"
                result = api.search_commits(query, page=page)
                if not result or not result.get("items"):
                    break
                for item in result["items"]:
                    sha = item["sha"]
                    msg = item.get("commit", {}).get("message", "")
                    commit_data = api.get_commit(owner, name, sha)
                    if not commit_data or "files" not in commit_data:
                        continue
                    for f in commit_data["files"]:
                        fpath = f.get("filename", "")
                        lang = detect_language(fpath)
                        if not lang:
                            continue
                        patch = f.get("patch", "")
                        if not patch or len(patch) < MIN_CODE_LEN:
                            continue
                        # 提取被删除的代码（修复前 = 漏洞代码）
                        vuln_code = extract_diff_removed(patch)
                        if len(vuln_code) < MIN_CODE_LEN:
                            # 尝试获取修复前的完整文件
                            parents = commit_data.get("parents", [])
                            if parents:
                                parent_sha = parents[0]["sha"]
                                full_src = api.get_file_content(owner, name, fpath, ref=parent_sha)
                                if full_src:
                                    match_pos = full_src.find(vuln_code[:30]) if vuln_code else -1
                                    if match_pos >= 0:
                                        extractor = extract_function_cpp if lang == "C++" else extract_function_python
                                        snippet = extractor(full_src, match_pos)
                                        if snippet:
                                            vuln_code = snippet
                        if len(vuln_code) < MIN_CODE_LEN or len(vuln_code) > MAX_CODE_LEN:
                            continue
                        cwe_result = classify_cwe(vuln_code, msg)
                        cwe_id = cwe_result[0] if cwe_result else None
                        cwe_name = cwe_result[1] if cwe_result else None
                        severity = cwe_result[2] if cwe_result else "MEDIUM"
                        record_id = make_id(repo, cwe_id, vuln_code)
                        if progress.is_dup(record_id, vuln_code):
                            continue
                        desc = f"来自 {repo} 的安全修复 commit {sha[:8]}。{msg[:100]}"
                        yield {
                            "id": record_id, "repo": repo,
                            "cwe_id": cwe_id, "cwe_name": cwe_name,
                            "language": lang, "vulnerable_code": vuln_code,
                            "label": 1, "severity": severity,
                            "description": desc,
                        }
                progress.cursors[cursor_key] = page + 1

# ─────────────────────────────────────────────
# 策略 B：漏洞模式代码搜索
# ─────────────────────────────────────────────
def strategy_vuln_patterns(api: GitHubAPI, progress: ProgressManager) -> Iterator[dict]:
    """在机器人仓库中搜索已知漏洞模式的代码。"""
    for cwe_id, (cwe_name, severity, patterns) in CWE_MAP.items():
        for pattern in patterns:
            for repo in ROBOTICS_REPOS:
                owner, name = repo.split("/")
                cursor_key = f"pattern_{cwe_id}_{pattern}_{repo}"
                if progress.cursors.get(cursor_key) == "done":
                    continue
                lang_filter = "language:cpp" if "(" in pattern and pattern[0].islower() else ""
                if "os." in pattern or "subprocess" in pattern or "isinstance" in pattern:
                    lang_filter = "language:python"
                query = f'"{pattern}" repo:{repo} {lang_filter}'
                result = api.search_code(query)
                if not result or not result.get("items"):
                    progress.cursors[cursor_key] = "done"
                    continue
                for item in result["items"][:5]:  # 每个查询最多取 5 个文件
                    fpath = item.get("path", "")
                    lang = detect_language(fpath)
                    if not lang:
                        continue
                    source = api.get_file_content(owner, name, fpath)
                    if not source:
                        continue
                    # 找到 pattern 位置并提取函数
                    pos = source.find(pattern)
                    if pos < 0:
                        continue
                    extractor = extract_function_cpp if lang == "C++" else extract_function_python
                    snippet = extractor(source, pos)
                    if not snippet:
                        continue
                    record_id = make_id(repo, cwe_id, snippet)
                    if progress.is_dup(record_id, snippet):
                        continue
                    desc = f"在 {repo}/{fpath} 中发现 {cwe_name} 相关模式 ({pattern})"
                    yield {
                        "id": record_id, "repo": repo,
                        "cwe_id": cwe_id, "cwe_name": cwe_name,
                        "language": lang, "vulnerable_code": snippet,
                        "label": 1, "severity": severity,
                        "description": desc,
                    }
                progress.cursors[cursor_key] = "done"

# ─────────────────────────────────────────────
# 策略 C：安全代码采样（label=0）
# ─────────────────────────────────────────────
def strategy_benign_code(api: GitHubAPI, progress: ProgressManager) -> Iterator[dict]:
    """从机器人仓库中采样安全代码。"""
    all_patterns = SAFE_PATTERNS_CPP + SAFE_PATTERNS_PY
    repos = list(ROBOTICS_REPOS)
    random.shuffle(repos)
    for repo in repos:
        owner, name = repo.split("/")
        for pattern in all_patterns:
            cursor_key = f"benign_{pattern}_{repo}"
            if progress.cursors.get(cursor_key) == "done":
                continue
            lang_filter = "language:cpp" if pattern in SAFE_PATTERNS_CPP else "language:python"
            query = f'"{pattern}" repo:{repo} {lang_filter}'
            result = api.search_code(query)
            if not result or not result.get("items"):
                progress.cursors[cursor_key] = "done"
                continue
            for item in result["items"][:3]:
                fpath = item.get("path", "")
                lang = detect_language(fpath)
                if not lang:
                    continue
                source = api.get_file_content(owner, name, fpath)
                if not source:
                    continue
                pos = source.find(pattern)
                if pos < 0:
                    continue
                extractor = extract_function_cpp if lang == "C++" else extract_function_python
                snippet = extractor(source, pos)
                if not snippet:
                    continue
                # 排除含漏洞模式的代码
                has_vuln = False
                for _, (_, _, vuln_pats) in CWE_MAP.items():
                    for vp in vuln_pats:
                        if vp in snippet and pattern not in ("try:", "with open("):
                            has_vuln = True
                            break
                    if has_vuln:
                        break
                if has_vuln:
                    continue
                record_id = make_id(repo, None, snippet)
                if progress.is_dup(record_id, snippet):
                    continue
                desc = f"来自 {repo}/{fpath} 的安全代码示例，使用了 {pattern}"
                yield {
                    "id": record_id, "repo": repo,
                    "cwe_id": None, "cwe_name": None,
                    "language": lang, "vulnerable_code": snippet,
                    "label": 0, "severity": "NONE",
                    "description": desc,
                }
            progress.cursors[cursor_key] = "done"

# ─────────────────────────────────────────────
# RAG 语料生成
# ─────────────────────────────────────────────
def generate_rag_corpus(dataset_path: Path, output_path: Path):
    """从数据集生成 RAG 语料库。"""
    print("\n[rag] 生成 RAG 语料库 ...")
    entries = []
    with open(dataset_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            rid = record["id"]
            if record["label"] == 1 and record.get("cwe_id"):
                # 历史漏洞条目
                entries.append({
                    "id": f"hist_{rid}",
                    "type": "historical_vulnerability",
                    "content": record["vulnerable_code"],
                    "metadata": {
                        "cwe_id": record["cwe_id"],
                        "repo": record["repo"],
                        "severity": record["severity"],
                        "description": record["description"],
                    }
                })
            elif record["label"] == 0:
                # 安全模式条目
                entries.append({
                    "id": f"safe_{rid}",
                    "type": "ros_semantic_pattern",
                    "content": record["vulnerable_code"],
                    "metadata": {
                        "repo": record["repo"],
                        "is_safe_pattern": True,
                        "language": record["language"],
                    }
                })
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    print(f"[rag] 生成 {len(entries)} 条 RAG 语料 -> {output_path}")


# ─────────────────────────────────────────────
# 主流程
# ─────────────────────────────────────────────
def main():
    if not GITHUB_TOKEN:
        print("警告: 未设置 GITHUB_TOKEN，API 限额仅 60次/小时，建议在 .env 中配置")
        print("  GITHUB_TOKEN=ghp_xxxx")
        print()

    api = GitHubAPI(GITHUB_TOKEN)
    progress = ProgressManager(PROGRESS_PATH)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    target_vuln = int(TARGET_TOTAL * VULN_RATIO)
    target_benign = TARGET_TOTAL - target_vuln

    # ── Phase 1: 漏洞样本 (label=1) ──
    vuln_count = progress.counts["label_1"]
    print(f"\n{'='*50}")
    print(f"Phase 1: 爬取漏洞样本 (目标 {target_vuln}，已有 {vuln_count})")
    print(f"{'='*50}")

    strategies_vuln = [
        ("安全修复Commit", strategy_security_commits),
        ("漏洞模式搜索", strategy_vuln_patterns),
    ]

    with open(OUTPUT_PATH, "a", encoding="utf-8") as f:
        for sname, sfunc in strategies_vuln:
            if vuln_count >= target_vuln:
                break
            print(f"\n[{sname}] 开始 ...")
            try:
                for record in sfunc(api, progress):
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
                    f.flush()
                    progress.mark(record["id"], record["vulnerable_code"], 1)
                    vuln_count += 1
                    if vuln_count % 5 == 0:
                        progress.save()
                        print(f"  [{sname}] 漏洞样本: {vuln_count}/{target_vuln} "
                              f"(API调用: {api.call_count})")
                    if vuln_count >= target_vuln:
                        break
            except KeyboardInterrupt:
                print("\n[中断] 保存进度 ...")
                progress.save()
                break

    # ── Phase 2: 安全样本 (label=0) ──
    benign_count = progress.counts["label_0"]
    actual_target_benign = max(vuln_count, target_benign)
    print(f"\n{'='*50}")
    print(f"Phase 2: 爬取安全样本 (目标 {actual_target_benign}，已有 {benign_count})")
    print(f"{'='*50}")

    with open(OUTPUT_PATH, "a", encoding="utf-8") as f:
        try:
            for record in strategy_benign_code(api, progress):
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
                f.flush()
                progress.mark(record["id"], record["vulnerable_code"], 0)
                benign_count += 1
                if benign_count % 5 == 0:
                    progress.save()
                    print(f"  [安全代码] 安全样本: {benign_count}/{actual_target_benign} "
                          f"(API调用: {api.call_count})")
                if benign_count >= actual_target_benign:
                    break
        except KeyboardInterrupt:
            print("\n[中断] 保存进度 ...")

    progress.save()

    # ── Phase 3: 生成 RAG 语料 ──
    total = vuln_count + benign_count
    print(f"\n{'='*50}")
    print(f"爬取完成！漏洞: {vuln_count}, 安全: {benign_count}, 总计: {total}")
    print(f"API 调用次数: {api.call_count}")
    print(f"{'='*50}")

    if total > 0:
        generate_rag_corpus(OUTPUT_PATH, RAG_OUTPUT_PATH)

    print(f"\n输出文件:")
    print(f"  数据集: {OUTPUT_PATH}")
    print(f"  RAG语料: {RAG_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
