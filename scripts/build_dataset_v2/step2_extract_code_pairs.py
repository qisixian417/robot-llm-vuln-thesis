#!/usr/bin/env python3
"""
Step 2: 从 CVE 的 GitHub commit URL 提取成对代码。
修复前函数 (label=1) + 修复后函数 (label=0)
输出：data_v2/raw/cve_pairs.jsonl
"""

import json
import os
import re
import time
import requests
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
INPUT = ROOT / "data_v2" / "raw" / "cve_list.jsonl"
OUTPUT = ROOT / "data_v2" / "raw" / "cve_pairs.jsonl"

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}" if GITHUB_TOKEN else "",
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "robot-vuln-research/1.0",
}


def parse_commit_url(url: str):
    """从 GitHub commit URL 提取 owner/repo/commit_sha"""
    pattern = r"github\.com/([^/]+)/([^/]+)/commit/([a-f0-9]+)"
    m = re.search(pattern, url)
    if m:
        return m.group(1), m.group(2), m.group(3)
    return None, None, None


def get_commit_diff(owner: str, repo: str, sha: str):
    """获取 commit 的 diff 信息"""
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        if resp.status_code == 404:
            return None
        if resp.status_code == 403:
            print(f"  [限速] 等待 60 秒...")
            time.sleep(60)
            resp = requests.get(url, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"  [错误] {owner}/{repo}/{sha}: {e}")
        return None


def extract_functions_from_patch(patch: str):
    """从 patch 文本中提取修复前和修复后的代码块"""
    if not patch:
        return None, None

    before_lines = []
    after_lines = []

    for line in patch.split("\n"):
        if line.startswith("@@"):
            continue
        if line.startswith("-") and not line.startswith("---"):
            before_lines.append(line[1:])
        elif line.startswith("+") and not line.startswith("+++"):
            after_lines.append(line[1:])
        else:
            # 上下文行，两边都有
            before_lines.append(line[1:] if line.startswith(" ") else line)
            after_lines.append(line[1:] if line.startswith(" ") else line)

    before_code = "\n".join(before_lines).strip()
    after_code = "\n".join(after_lines).strip()

    return before_code, after_code


def is_target_language(filename: str) -> str:
    """判断是否是目标语言"""
    if filename.endswith(".cpp") or filename.endswith(".cc") or filename.endswith(".c") or filename.endswith(".h"):
        return "C++"
    if filename.endswith(".py"):
        return "Python"
    return ""


def is_valid_code(code: str) -> bool:
    """基本质量过滤"""
    if not code:
        return False
    lines = [l for l in code.split("\n") if l.strip()]
    return len(lines) >= 3 and len(code) >= 50


def process_commit(cve_record: dict):
    """处理一条 CVE 记录，提取所有代码对"""
    pairs = []
    cve_id = cve_record["cve_id"]
    cwe_ids = cve_record.get("cwe_ids", [])

    for commit_url in cve_record.get("github_commit_urls", []):
        owner, repo, sha = parse_commit_url(commit_url)
        if not owner:
            continue

        commit_data = get_commit_diff(owner, repo, sha)
        if not commit_data:
            continue

        files = commit_data.get("files", [])
        for file_info in files:
            filename = file_info.get("filename", "")
            language = is_target_language(filename)
            if not language:
                continue

            patch = file_info.get("patch", "")
            if not patch:
                continue

            before_code, after_code = extract_functions_from_patch(patch)

            if not is_valid_code(before_code) or not is_valid_code(after_code):
                continue

            # 正样本（修复前，有漏洞）
            pairs.append({
                "id": f"{cve_id}_{owner}_{repo}_{sha[:8]}_vuln",
                "cve_id": cve_id,
                "cwe_id": cwe_ids[0] if cwe_ids else None,
                "cwe_ids": cwe_ids,
                "repo": f"{owner}/{repo}",
                "commit_sha": sha,
                "filename": filename,
                "language": language,
                "vulnerable_code": before_code,
                "label": 1,
                "pair_type": "cve_before",
                "description": cve_record.get("description", "")[:300],
            })

            # 负样本（修复后，干净）
            pairs.append({
                "id": f"{cve_id}_{owner}_{repo}_{sha[:8]}_clean",
                "cve_id": cve_id,
                "cwe_id": cwe_ids[0] if cwe_ids else None,
                "cwe_ids": cwe_ids,
                "repo": f"{owner}/{repo}",
                "commit_sha": sha,
                "filename": filename,
                "language": language,
                "vulnerable_code": after_code,
                "label": 0,
                "pair_type": "cve_after",
                "description": cve_record.get("description", "")[:300],
            })

        time.sleep(1)  # GitHub API 限速

    return pairs


def main():
    if not INPUT.exists():
        print(f"ERROR: {INPUT} 不存在，请先运行 step1_fetch_cve.py")
        return

    cve_records = []
    with open(INPUT, encoding="utf-8") as f:
        for line in f:
            cve_records.append(json.loads(line))

    print(f"读取 {len(cve_records)} 条 CVE 记录")

    all_pairs = []
    for i, record in enumerate(cve_records):
        print(f"[{i+1}/{len(cve_records)}] {record['cve_id']}")
        pairs = process_commit(record)
        all_pairs.extend(pairs)
        print(f"  提取 {len(pairs)} 条代码对，累计 {len(all_pairs)} 条")

        # 每 10 条保存一次
        if (i + 1) % 10 == 0:
            with open(OUTPUT, "w", encoding="utf-8") as f:
                for p in all_pairs:
                    f.write(json.dumps(p, ensure_ascii=False) + "\n")

    with open(OUTPUT, "w", encoding="utf-8") as f:
        for p in all_pairs:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")

    label1 = sum(1 for p in all_pairs if p["label"] == 1)
    label0 = sum(1 for p in all_pairs if p["label"] == 0)
    print(f"\n完成：总 {len(all_pairs)} 条，漏洞={label1}，干净={label0}")
    print(f"已保存到 {OUTPUT}")


if __name__ == "__main__":
    main()
