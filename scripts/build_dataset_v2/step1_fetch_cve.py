#!/usr/bin/env python3
"""
Step 1: 从 NVD API 搜索机器人相关 CVE，提取 CVE ID、官方 CWE、GitHub commit URL。
输出：data_v2/raw/cve_list.jsonl
"""

import json
import time
import requests
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT = ROOT / "data_v2" / "raw" / "cve_list.jsonl"
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

# 搜索关键词
KEYWORDS = [
    # ROS 核心通信层
    "rclcpp", "rcl", "ros_comm", "rclpy", "rcutils",
    # ROS 中间件
    "rmw", "fastdds", "Fast-DDS", "cyclonedds", "rosidl",
    # ROS 整体
    "ROS", "ros2",
    # ROS 工具链
    "rosbag", "ros2cli", "launch_ros",
    # 应用层（ROS 生态）
    "moveit", "navigation2",
]

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"User-Agent": "robot-vuln-research/1.0"}


def fetch_cves_by_keyword(keyword: str, delay: float = 6.0):
    """NVD API 免费版限速 5次/30秒，每次请求间隔 6 秒"""
    results = []
    start_index = 0
    results_per_page = 100

    while True:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }
        try:
            resp = requests.get(NVD_API, params=params, headers=HEADERS, timeout=30)
            if resp.status_code == 403:
                print(f"  [限速] 等待 30 秒...")
                time.sleep(30)
                continue
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            print(f"  [错误] {keyword} startIndex={start_index}: {e}")
            break

        vulnerabilities = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)
        print(f"  [{keyword}] {start_index}/{total} 共 {len(vulnerabilities)} 条")

        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")

            # 提取官方 CWE
            cwe_list = []
            for weakness in cve.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    val = desc.get("value", "")
                    if val.startswith("CWE-"):
                        cwe_list.append(val)

            # 只保留我们关注的 9 种 CWE
            TARGET_CWES = {
                "CWE-119", "CWE-401", "CWE-362", "CWE-476",
                "CWE-416", "CWE-190", "CWE-134", "CWE-78"
            }
            matched_cwes = [c for c in cwe_list if c in TARGET_CWES]
            if not matched_cwes and cwe_list:
                matched_cwes = cwe_list[:1]  # 保留第一个，后续再过滤

            # 提取 GitHub commit URL
            github_urls = []
            for ref in cve.get("references", []):
                url = ref.get("url", "")
                if "github.com" in url and "/commit/" in url:
                    github_urls.append(url)

            # 提取描述
            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            results.append({
                "cve_id": cve_id,
                "cwe_ids": matched_cwes,
                "all_cwes": cwe_list,
                "github_commit_urls": github_urls,
                "description": description,
                "keyword": keyword,
                "published": cve.get("published", ""),
            })

        start_index += results_per_page
        if start_index >= total:
            break
        time.sleep(delay)

    return results


def main():
    all_results = []
    seen_cve_ids = set()

    for keyword in KEYWORDS:
        print(f"\n搜索关键词: {keyword}")
        results = fetch_cves_by_keyword(keyword)
        for r in results:
            if r["cve_id"] not in seen_cve_ids:
                seen_cve_ids.add(r["cve_id"])
                all_results.append(r)
        print(f"  新增 {len(results)} 条，累计去重后 {len(all_results)} 条")
        time.sleep(6)

    # 过滤：只保留有 GitHub commit URL 的条目
    with_commit = [r for r in all_results if r["github_commit_urls"]]
    print(f"\n总 CVE: {len(all_results)}")
    print(f"有 GitHub commit URL: {len(with_commit)}")

    with open(OUTPUT, "w", encoding="utf-8") as f:
        for r in with_commit:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"已保存到 {OUTPUT}")


if __name__ == "__main__":
    main()
