#!/usr/bin/env python3
"""Step 3: 从 GitHub commit 关键词路爬取成对代码（漏洞前 + 修复后）

聚焦 core_middleware（ROS 核心通信层）仓库，代码长度限制 8-80 行。
负样本改为成对：从同一 commit 提取修复后函数（label=0），不再随机取其他函数。
"""

import json
import os
import re
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}

OUTPUT_PATH = ROOT / "data_v2" / "raw" / "commit_pairs.jsonl"
OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

# ── 代码长度限制 ──────────────────────────────────────────────────────────────
MIN_LINES = 8
MAX_LINES = 80

# ── core_middleware 仓库列表（ROS 核心通信层）────────────────────────────────
REPOS = [
    # ROS1 核心
    {"repo": "ros/ros_comm",         "component": "core_middleware"},
    {"repo": "ros/roscpp_core",      "component": "core_middleware"},
    {"repo": "ros/ros",              "component": "core_middleware"},
    {"repo": "ros/catkin",           "component": "core_middleware"},
    {"repo": "ros/std_msgs",         "component": "core_middleware"},
    {"repo": "ros/common_msgs",      "component": "core_middleware"},
    {"repo": "ros/actionlib",        "component": "core_middleware"},
    {"repo": "ros/dynamic_reconfigure", "component": "core_middleware"},
    # ROS2 核心
    {"repo": "ros2/rclcpp",          "component": "core_middleware"},
    {"repo": "ros2/rcl",             "component": "core_middleware"},
    {"repo": "ros2/rclpy",           "component": "core_middleware"},
    {"repo": "ros2/rcutils",         "component": "core_middleware"},
    {"repo": "ros2/rmw",             "component": "core_middleware"},
    {"repo": "ros2/rmw_implementation", "component": "core_middleware"},
    {"repo": "ros2/rosidl",          "component": "core_middleware"},
    {"repo": "ros2/rosbag2",         "component": "core_middleware"},
    {"repo": "ros2/launch",          "component": "core_middleware"},
    {"repo": "ros2/geometry2",       "component": "core_middleware"},
    {"repo": "ros2/common_interfaces", "component": "core_middleware"},
    {"repo": "ros2/ros2cli",         "component": "core_middleware"},
    # ROS2 DDS 中间件（底层通信）
    {"repo": "eclipse-cyclonedds/cyclonedds", "component": "core_middleware"},
    {"repo": "eProsima/Fast-DDS",    "component": "core_middleware"},
    {"repo": "eProsima/Fast-CDR",    "component": "core_middleware"},
    # 补充：ROS2 相关应用（和核心通信高度相关）
    {"repo": "ros-planning/navigation2", "component": "application"},
    {"repo": "ros-planning/moveit2",    "component": "application"},
    {"repo": "ros-perception/image_pipeline", "component": "perception"},
    {"repo": "ros/ros_tutorials",    "component": "core_middleware"},
    {"repo": "micro-ROS/micro_ros_arduino", "component": "embedded"},
    {"repo": "micro-ROS/rcl_executor", "component": "embedded"},
]

# 安全相关关键词（比旧版更严格）
SECURITY_KEYWORDS = [
    "CVE-",
    "security fix",
    "vulnerability",
    "buffer overflow",
    "stack overflow",
    "heap overflow",
    "use-after-free",
    "use after free",
    "memory leak",
    "null pointer",
    "null dereference",
    "integer overflow",
    "format string",
    "race condition",
    "data race",
    "out of bounds",
    "out-of-bounds",
    "arbitrary code",
    "remote code execution",
    "privilege escalation",
    "fix crash",
    "fix: crash",
    "fix null",
    "fix memory",
    "fix leak",
    "fix overflow",
    "fix race",
    "sanitizer",
    "asan",
    "tsan",
    "ubsan",
]

# 要排除的噪音关键词（commit message 中含这些词则跳过）
NOISE_KEYWORDS = [
    "merge pull request",
    "merge branch",
    "merge remote",
    "bump version",
    "update changelog",
    "update readme",
    "update documentation",
    "refactor",
    "cmake",
    "ci:",
    "[ci]",
    "clang-format",
    "typo",
    "lint",
    "style:",
    "chore:",
    "docs:",
    "test:",
    "revert:",
]

C_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}
PY_EXTENSIONS = {".py"}


def gh_get(url, params=None, retry=3):
    """GitHub API GET，带重试和 rate limit 处理。"""
    for attempt in range(retry):
        try:
            r = requests.get(url, headers=HEADERS, params=params, timeout=30)
            if r.status_code == 403 and "rate limit" in r.text.lower():
                reset_ts = int(r.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait = max(reset_ts - time.time(), 0) + 5
                print(f"  [rate limit] 等待 {wait:.0f}s...")
                time.sleep(wait)
                continue
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if attempt < retry - 1:
                time.sleep(5)
            else:
                print(f"  [error] {url}: {e}")
                return None
    return None


def is_security_commit(message: str) -> bool:
    """判断 commit message 是否是安全修复。"""
    msg_lower = message.lower()
    # 先检查噪音关键词
    for noise in NOISE_KEYWORDS:
        if noise in msg_lower:
            return False
    # 再检查安全关键词
    for kw in SECURITY_KEYWORDS:
        if kw.lower() in msg_lower:
            return True
    return False


def extract_function_from_patch(patch_lines: list, is_before: bool) -> str:
    """从 patch 行中提取修改前（is_before=True）或修改后（is_before=False）的代码。"""
    result = []
    for line in patch_lines:
        if line.startswith("@@"):
            continue
        if is_before:
            # 修改前：保留上下文行（空格开头）和删除行（-号），跳过新增行（+号）
            if line.startswith("+"):
                continue
            result.append(line[1:] if line.startswith("-") else line[1:] if line.startswith(" ") else line)
        else:
            # 修改后：保留上下文行和新增行，跳过删除行
            if line.startswith("-"):
                continue
            result.append(line[1:] if line.startswith("+") else line[1:] if line.startswith(" ") else line)
    return "\n".join(result)


def get_full_function(repo: str, file_path: str, commit_sha: str, is_before: bool) -> str:
    """获取 commit 前或后的完整文件内容，然后尝试提取函数。"""
    sha = f"{commit_sha}^" if is_before else commit_sha
    url = f"https://api.github.com/repos/{repo}/contents/{file_path}"
    data = gh_get(url, params={"ref": sha})
    if not data or data.get("encoding") != "base64":
        return ""
    import base64
    try:
        content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return content
    except Exception:
        return ""


def extract_changed_functions_from_patch(patch: str, file_ext: str):
    """从 diff patch 中提取被修改函数的前后版本。"""
    if not patch:
        return []

    pairs = []
    lines = patch.split("\n")
    hunks = []
    current_hunk = []

    for line in lines:
        if line.startswith("@@"):
            if current_hunk:
                hunks.append(current_hunk)
            current_hunk = [line]
        else:
            current_hunk.append(line)
    if current_hunk:
        hunks.append(current_hunk)

    for hunk in hunks:
        before_code = extract_function_from_patch(hunk, is_before=True).strip()
        after_code = extract_function_from_patch(hunk, is_before=False).strip()

        if not before_code or not after_code:
            continue

        before_lines = [l for l in before_code.split("\n") if l.strip()]
        after_lines = [l for l in after_code.split("\n") if l.strip()]

        # 长度过滤：8-80 行
        if not (MIN_LINES <= len(before_lines) <= MAX_LINES):
            continue
        if not (MIN_LINES <= len(after_lines) <= MAX_LINES):
            continue

        # 确保有实质性修改（前后不完全相同）
        if before_code == after_code:
            continue

        language = "C++" if file_ext in C_EXTENSIONS else "Python"
        pairs.append({
            "before": before_code,
            "after": after_code,
            "language": language,
        })

    return pairs


def process_repo(repo_info: dict, existing_ids: set):
    """爬取单个仓库的安全修复 commit，返回成对样本列表。"""
    repo = repo_info["repo"]
    component = repo_info["component"]
    pairs = []

    print(f"  搜索 {repo} ...")

    # 获取 commit 列表（最多爬 5 页，每页 100 条）
    commits_seen = set()
    for page in range(1, 6):
        url = f"https://api.github.com/repos/{repo}/commits"
        data = gh_get(url, params={"per_page": 100, "page": page})
        if not data:
            break
        if len(data) == 0:
            break

        for commit in data:
            sha = commit["sha"]
            if sha in commits_seen:
                continue
            commits_seen.add(sha)

            message = commit.get("commit", {}).get("message", "")
            if not is_security_commit(message):
                continue

            # 获取 commit 详情（含文件 diff）
            detail = gh_get(f"https://api.github.com/repos/{repo}/commits/{sha}")
            if not detail:
                continue

            files = detail.get("files", [])
            for f in files:
                filename = f.get("filename", "")
                ext = Path(filename).suffix.lower()
                if ext not in C_EXTENSIONS and ext not in PY_EXTENSIONS:
                    continue

                patch = f.get("patch", "")
                if not patch:
                    continue

                # 提取成对代码（hunk 级别）
                code_pairs = extract_changed_functions_from_patch(patch, ext)
                for cp in code_pairs:
                    # 生成唯一 ID
                    import hashlib
                    h = hashlib.md5(cp["before"].encode()).hexdigest()[:8]
                    sample_id = f"{repo.replace('/', '_')}_vuln_{h}"
                    if sample_id in existing_ids:
                        continue

                    # 提取 CWE 线索（如果 commit message 有）
                    cwe_match = re.search(r"CWE-(\d+)", message, re.IGNORECASE)
                    cwe_hint = f"CWE-{cwe_match.group(1)}" if cwe_match else None

                    # 漏洞样本
                    pairs.append({
                        "id": sample_id,
                        "repo": repo,
                        "ros_component": component,
                        "ros_version": "ROS2" if "ros2" in repo.lower() or "cyclone" in repo.lower() or "fastdds" in repo.lower().replace("-", "") else "ROS1",
                        "language": cp["language"],
                        "label": 1,
                        "vulnerable_code": cp["before"],
                        "fixed_code": cp["after"],
                        "commit_sha": sha,
                        "file_path": filename,
                        "commit_message": message[:300],
                        "cwe_hint": cwe_hint,
                        "source": "commit_keyword",
                        "severity": "UNKNOWN",
                    })
                    existing_ids.add(sample_id)

                    # 成对负样本（修复后代码）
                    h2 = hashlib.md5(cp["after"].encode()).hexdigest()[:8]
                    clean_id = f"{repo.replace('/', '_')}_clean_{h2}"
                    if clean_id not in existing_ids:
                        pairs.append({
                            "id": clean_id,
                            "repo": repo,
                            "ros_component": component,
                            "ros_version": "ROS2" if "ros2" in repo.lower() else "ROS1",
                            "language": cp["language"],
                            "label": 0,
                            "vulnerable_code": cp["after"],
                            "fixed_code": None,
                            "commit_sha": sha,
                            "file_path": filename,
                            "commit_message": message[:300],
                            "cwe_hint": None,
                            "source": "paired_fix",
                            "severity": "NONE",
                        })
                        existing_ids.add(clean_id)

        # 避免触发 rate limit
        time.sleep(1)

    return pairs


def main():
    # 加载已有数据（断点续跑）
    existing = []
    existing_ids = set()
    if OUTPUT_PATH.exists():
        with open(OUTPUT_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    item = json.loads(line)
                    existing.append(item)
                    existing_ids.add(item["id"])
        print(f"断点续跑：已有 {len(existing)} 条，跳过已处理样本")

    all_pairs = list(existing)
    total_repos = len(REPOS)

    with open(OUTPUT_PATH, "a", encoding="utf-8") as out:
        for i, repo_info in enumerate(REPOS):
            repo = repo_info["repo"]
            print(f"\n[{i+1}/{total_repos}] {repo}")

            # 检查是否已经爬过这个仓库
            already_done = any(p["repo"] == repo for p in existing)
            if already_done:
                count = sum(1 for p in existing if p["repo"] == repo)
                print(f"  跳过（已有 {count} 条）")
                continue

            pairs = process_repo(repo_info, existing_ids)
            vuln_count = sum(1 for p in pairs if p["label"] == 1)
            clean_count = sum(1 for p in pairs if p["label"] == 0)
            print(f"  新增 {len(pairs)} 条（漏洞={vuln_count}, 干净={clean_count}），累计 {len(all_pairs) + len(pairs)} 条")

            for p in pairs:
                out.write(json.dumps(p, ensure_ascii=False) + "\n")
            out.flush()

            all_pairs.extend(pairs)
            time.sleep(2)

    vuln_total = sum(1 for p in all_pairs if p["label"] == 1)
    clean_total = sum(1 for p in all_pairs if p["label"] == 0)
    print(f"\n完成！总计 {len(all_pairs)} 条（漏洞={vuln_total}, 干净={clean_total}）")
    print(f"输出：{OUTPUT_PATH}")


if __name__ == "__main__":
    main()
