#!/usr/bin/env python3
"""
Expand dataset by collecting new vulnerability samples from ROS/robot GitHub repos.
Target: ~250-300 new samples from repos NOT in existing dataset.
"""

import json
import os
import re
import ssl
import time
import urllib.request
import urllib.parse
from pathlib import Path
from typing import List, Dict, Optional
from dotenv import load_dotenv

# Project root
ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

# Target repos (NOT in existing 32 repos)
NEW_REPOS = [
    "ros-planning/moveit2",
    "ros-planning/navigation2",
    "gazebosim/gz-physics",
    "gazebosim/gz-rendering",
    "gazebosim/gz-sensors",
    "micro-ROS/micro_ros_setup",
    "ros-perception/image_common",
    "ros-perception/image_pipeline",
    "SteveMacenski/slam_toolbox",
    "mavlink/mavros",
    "autowarefoundation/autoware.universe",
    "ros2/launch",
    "ros2/rmw",
]

SECURITY_KEYWORDS = [
    "fix", "security", "vulnerability", "overflow", "leak",
    "race", "crash", "null pointer", "use after free",
    "memory", "segfault", "CVE",
]

CWE_MAP = {
    "CWE-362": "Race Condition",
    "CWE-401": "Memory Leak",
    "CWE-190": "Integer Overflow",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-134": "Use of Externally-Controlled Format String",
    "CWE-416": "Use After Free",
    "CWE-78": "OS Command Injection",
    "CWE-119": "Buffer Overflow",
}

GITHUB_API = "https://api.github.com"
DASHSCOPE_API = "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
MODEL = "qwen-plus"

OUTPUT_FILE = ROOT / "data" / "github_expanded_samples.jsonl"

CPP_EXTS = {".cpp", ".cc", ".c", ".h", ".hpp"}
PY_EXTS = {".py"}

# SSL workaround for macOS
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# --- API helpers ---

def github_get(url: str, token: str, accept: str = "application/vnd.github+json") -> Optional[dict]:
    """GET request to GitHub API with error handling."""
    req = urllib.request.Request(url, headers={
        "Authorization": f"token {token}",
        "Accept": accept,
        "User-Agent": "RoboGuard-Dataset-Collector",
    })
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"  [WARN] Rate limited, sleeping 60s...")
            time.sleep(60)
            return github_get(url, token, accept)
        print(f"  [ERR] HTTP {e.code} for {url}")
        return None
    except Exception as e:
        print(f"  [ERR] {e} for {url}")
        return None


def dashscope_classify(code: str, commit_msg: str, api_key: str) -> Optional[str]:
    """Use qwen-plus to classify CWE type. Returns CWE-XXX or None."""
    cwe_list = ", ".join(f"{k} ({v})" for k, v in CWE_MAP.items())
    prompt = (
        f"Analyze this code from a security commit and classify the vulnerability type.\n"
        f"Commit message: {commit_msg}\n\n"
        f"Code:\n```\n{code[:3000]}\n```\n\n"
        f"Choose ONE CWE from: {cwe_list}\n"
        f"If none match or this is not a real vulnerability, respond with: NONE\n"
        f"Respond with ONLY the CWE ID (e.g. CWE-362) or NONE."
    )
    body = json.dumps({
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 50,
    }).encode()
    req = urllib.request.Request(DASHSCOPE_API, data=body, headers={
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=60) as resp:
            data = json.loads(resp.read().decode())
            text = data["choices"][0]["message"]["content"].strip()
            match = re.search(r"CWE-\d+", text)
            return match.group(0) if match and match.group(0) in CWE_MAP else None
    except Exception as e:
        print(f"  [ERR] DashScope: {e}")
        return None

# --- PLACEHOLDER_FUNCTIONS ---


def extract_functions_from_patch(patch: str, filename: str) -> List[Dict]:
    """Extract function-level code from a git patch/diff."""
    ext = Path(filename).suffix.lower()
    functions = []

    if ext in CPP_EXTS:
        functions = _extract_cpp_functions(patch)
        lang = "C++"
    elif ext in PY_EXTS:
        functions = _extract_py_functions(patch)
        lang = "Python"
    else:
        return []

    return [{"code": f, "language": lang} for f in functions if f.count("\n") >= 4]


def _extract_cpp_functions(patch: str) -> List[str]:
    """Extract C++ functions from patch. Uses @@ context and + lines."""
    results = []
    # Split into hunks
    hunks = re.split(r"^@@[^@]+@@\s*(.*)", patch, flags=re.MULTILINE)
    for i in range(1, len(hunks), 2):
        context_line = hunks[i] if i < len(hunks) else ""
        hunk_body = hunks[i + 1] if i + 1 < len(hunks) else ""
        # Collect added lines (strip leading +)
        added = []
        for line in hunk_body.split("\n"):
            if line.startswith("+") and not line.startswith("+++"):
                added.append(line[1:])
            elif not line.startswith("-"):
                added.append(line)
        code_block = "\n".join(added).strip()
        if not code_block:
            continue
        # Try to find function boundaries
        func_pattern = re.compile(
            r"(?:[\w:*&<>\[\]]+\s+)+(\w+)\s*\([^)]*\)\s*(?:const\s*)?(?:override\s*)?\{",
            re.MULTILINE,
        )
        for m in func_pattern.finditer(code_block):
            start = m.start()
            brace = 1
            pos = m.end()
            while pos < len(code_block) and brace > 0:
                if code_block[pos] == "{":
                    brace += 1
                elif code_block[pos] == "}":
                    brace -= 1
                pos += 1
            if brace == 0:
                results.append(code_block[start:pos].strip())
        # Fallback: if no function found, use the whole added block
        if not results and len(added) >= 5:
            results.append(code_block)
    return results


def _extract_py_functions(patch: str) -> List[str]:
    """Extract Python functions from patch."""
    results = []
    added = []
    for line in patch.split("\n"):
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
        elif not line.startswith("-"):
            added.append(line)
    code_block = "\n".join(added)
    # Find def blocks
    func_pattern = re.compile(r"^([ \t]*)def\s+\w+\s*\(", re.MULTILINE)
    matches = list(func_pattern.finditer(code_block))
    for idx, m in enumerate(matches):
        start = m.start()
        indent = len(m.group(1))
        # Find end: next line with same or less indent (or next def or end)
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(code_block)
        func_code = code_block[start:end].rstrip()
        if func_code:
            results.append(func_code)
    return results


# --- PLACEHOLDER_SEARCH ---


def search_security_commits(repo: str, token: str, max_commits: int = 30) -> List[dict]:
    """Search for security-related commits in a repo."""
    seen_shas = set()
    commits = []
    for kw in SECURITY_KEYWORDS:
        if len(commits) >= max_commits:
            break
        q = urllib.parse.quote(f"repo:{repo} {kw}")
        url = f"{GITHUB_API}/search/commits?q={q}&sort=committer-date&per_page=5"
        data = github_get(url, token, accept="application/vnd.github.cloak-preview+json")
        time.sleep(1)
        if not data or "items" not in data:
            continue
        for item in data["items"]:
            sha = item["sha"]
            if sha in seen_shas:
                continue
            seen_shas.add(sha)
            commits.append({
                "sha": sha,
                "message": item.get("commit", {}).get("message", ""),
            })
            if len(commits) >= max_commits:
                break
    print(f"  Found {len(commits)} unique security commits")
    return commits


def fetch_benign_commits(repo: str, token: str, count: int = 10) -> List[dict]:
    """Fetch recent non-security commits for benign samples."""
    url = f"{GITHUB_API}/repos/{repo}/commits?per_page={count}"
    data = github_get(url, token)
    time.sleep(1)
    if not data or not isinstance(data, list):
        return []
    sec_lower = [kw.lower() for kw in SECURITY_KEYWORDS]
    benign = []
    for item in data:
        msg = item.get("commit", {}).get("message", "").lower()
        if not any(kw in msg for kw in sec_lower):
            benign.append({
                "sha": item["sha"],
                "message": item.get("commit", {}).get("message", ""),
            })
    print(f"  Found {len(benign)} benign commits")
    return benign


def process_commit(repo: str, sha: str, message: str, token: str,
                   api_key: str, is_vuln: bool) -> List[dict]:
    """Fetch commit details and extract function samples."""
    url = f"{GITHUB_API}/repos/{repo}/commits/{sha}"
    data = github_get(url, token)
    time.sleep(1)
    if not data or "files" not in data:
        return []
    samples = []
    for f in data["files"]:
        fname = f.get("filename", "")
        patch = f.get("patch", "")
        if not patch:
            continue
        funcs = extract_functions_from_patch(patch, fname)
        for func_info in funcs:
            code = func_info["code"]
            lang = func_info["language"]
            if is_vuln:
                cwe = dashscope_classify(code, message, api_key)
                time.sleep(2)
                if not cwe:
                    continue
                repo_short = repo.split("/")[-1]
                sample_id = f"{repo_short}_{cwe}_{sha[:8]}"
                samples.append({
                    "id": sample_id,
                    "repo": repo,
                    "cwe_id": cwe,
                    "cwe_name": CWE_MAP.get(cwe, "Unknown"),
                    "language": lang,
                    "vulnerable_code": code,
                    "label": 1,
                    "severity": "MEDIUM",
                    "description": message.split("\n")[0][:200],
                    "source": "github_expanded",
                })
            else:
                repo_short = repo.split("/")[-1]
                sample_id = f"{repo_short}_benign_{sha[:8]}"
                samples.append({
                    "id": sample_id,
                    "repo": repo,
                    "cwe_id": "",
                    "cwe_name": "",
                    "language": lang,
                    "vulnerable_code": code,
                    "label": 0,
                    "severity": "",
                    "description": message.split("\n")[0][:200],
                    "source": "github_expanded",
                })
            # Only take first function per file to avoid duplicates
            break
    return samples


# --- PLACEHOLDER_MAIN ---


def load_existing_ids() -> set:
    """Load existing sample IDs to avoid duplicates."""
    ids = set()
    for fname in ["dataset_cleaned.jsonl", "github_expanded_samples.jsonl"]:
        p = ROOT / "data" / fname
        if p.exists():
            with open(p) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            ids.add(json.loads(line)["id"])
                        except (json.JSONDecodeError, KeyError):
                            pass
    return ids


def load_processed_repos() -> set:
    """Load repos already processed (for --resume)."""
    repos = set()
    p = OUTPUT_FILE
    if p.exists():
        with open(p) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        repos.add(json.loads(line)["repo"])
                    except (json.JSONDecodeError, KeyError):
                        pass
    return repos


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Expand dataset from new GitHub repos")
    parser.add_argument("--limit", type=int, default=20,
                        help="Max samples per repo (default: 20)")
    parser.add_argument("--resume", action="store_true",
                        help="Skip repos already in output file")
    args = parser.parse_args()

    token = os.getenv("GITHUB_TOKEN")
    api_key = os.getenv("DASHSCOPE_API_KEY")
    if not token:
        print("ERROR: GITHUB_TOKEN not set in .env")
        return
    if not api_key:
        print("ERROR: DASHSCOPE_API_KEY not set in .env")
        return

    existing_ids = load_existing_ids()
    processed_repos = load_processed_repos() if args.resume else set()
    print(f"Existing sample IDs: {len(existing_ids)}")
    print(f"Output file: {OUTPUT_FILE}")
    print(f"Limit per repo: {args.limit}")
    print(f"Resume mode: {args.resume}")
    print()

    total_new = 0
    # Open in append mode
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    for repo in NEW_REPOS:
        print(f"=== Processing {repo} ===")
        if args.resume and repo in processed_repos:
            print(f"  Skipping (already processed)")
            continue

        repo_samples = []
        vuln_target = args.limit * 2 // 3  # ~2/3 vulnerable
        benign_target = args.limit - vuln_target  # ~1/3 benign

        # 1. Security commits -> vulnerable samples
        print(f"  Searching security commits (target: {vuln_target} vuln samples)...")
        sec_commits = search_security_commits(repo, token, max_commits=vuln_target * 2)
        vuln_count = 0
        for ci, commit in enumerate(sec_commits):
            if vuln_count >= vuln_target:
                break
            print(f"  [{ci+1}/{len(sec_commits)}] Processing {commit['sha'][:8]}: "
                  f"{commit['message'].split(chr(10))[0][:60]}...")
            samples = process_commit(repo, commit["sha"], commit["message"],
                                     token, api_key, is_vuln=True)
            for s in samples:
                if s["id"] not in existing_ids:
                    repo_samples.append(s)
                    existing_ids.add(s["id"])
                    vuln_count += 1
                    print(f"    + Vuln sample: {s['id']} ({s['cwe_id']})")
            if vuln_count >= vuln_target:
                break

        # 2. Benign commits -> benign samples
        print(f"  Fetching benign commits (target: {benign_target} benign samples)...")
        benign_commits = fetch_benign_commits(repo, token, count=benign_target * 3)
        benign_count = 0
        for ci, commit in enumerate(benign_commits):
            if benign_count >= benign_target:
                break
            print(f"  [benign {ci+1}/{len(benign_commits)}] Processing {commit['sha'][:8]}...")
            samples = process_commit(repo, commit["sha"], commit["message"],
                                     token, api_key, is_vuln=False)
            for s in samples:
                if s["id"] not in existing_ids:
                    repo_samples.append(s)
                    existing_ids.add(s["id"])
                    benign_count += 1
                    print(f"    + Benign sample: {s['id']}")
            if benign_count >= benign_target:
                break

        # Write samples for this repo
        if repo_samples:
            with open(OUTPUT_FILE, "a") as f:
                for s in repo_samples:
                    f.write(json.dumps(s, ensure_ascii=False) + "\n")
            total_new += len(repo_samples)
            print(f"  => Saved {len(repo_samples)} samples "
                  f"({vuln_count} vuln + {benign_count} benign)")
        else:
            print(f"  => No new samples found")
        print()

    print(f"=== Done! Total new samples: {total_new} ===")
    print(f"Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
