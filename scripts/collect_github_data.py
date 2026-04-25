#!/usr/bin/env python3
"""从GitHub收集机器人相关的安全漏洞数据"""

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

# GitHub搜索目标
ROBOT_REPOS = [
    # ROS核心
    "ros/ros_comm",
    "ros2/rclcpp",
    "ros2/rclpy",
    "ros2/rcl",
    "ros/ros",

    # Gazebo仿真
    "gazebosim/gz-sim",
    "gazebosim/gz-transport",
    "osrf/gazebo",

    # 自动驾驶
    "ApolloAuto/apollo",
    "autowarefoundation/autoware",
    "carla-simulator/carla",

    # 无人机
    "PX4/PX4-Autopilot",
    "ArduPilot/ardupilot",

    # 机器人框架
    "moveit/moveit",
    "ros-planning/navigation",
    "ros-controls/ros2_control",
    "eProsima/Fast-DDS",
]

# 目标CWE类型（需要扩充的）
TARGET_CWES = [
    "CWE-119",  # 缓冲区溢出
    "CWE-78",   # 命令注入
    "CWE-401",  # 内存泄漏
    "CWE-476",  # 空指针解引用
    "CWE-362",  # 竞态条件
    "CWE-416",  # Use After Free
    "CWE-190",  # 整数溢出
    "CWE-134",  # 格式化字符串
    "CWE-667",  # 锁定不当
    "CWE-404",  # 资源未正确释放
    "CWE-665",  # 初始化不当
    "CWE-754",  # 异常条件检查不当
]

# 安全相关关键词
SECURITY_KEYWORDS = [
    "security", "vulnerability", "CVE", "fix", "patch",
    "overflow", "injection", "leak", "race", "crash",
    "unsafe", "exploit", "malicious"
]


def search_github_commits(repo: str, keywords: List[str], max_results: int = 50) -> List[str]:
    """搜索GitHub仓库中的安全相关commit"""
    print(f"\n搜索仓库: {repo}")

    commit_shas = []

    for keyword in keywords[:3]:  # 限制关键词数量避免API限制
        try:
            # 使用gh命令搜索commit
            cmd = [
                "gh", "api",
                f"/repos/{repo}/commits",
                "-f", f"per_page=30",
                "--jq", ".[].sha"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                shas = result.stdout.strip().split('\n')
                commit_shas.extend(shas[:max_results])
                print(f"  找到 {len(shas)} 个commit")

            time.sleep(1)  # 避免API限制

        except Exception as e:
            print(f"  搜索失败: {e}")
            continue

    return list(set(commit_shas))[:max_results]


def get_commit_details(repo: str, sha: str) -> Optional[Dict[str, Any]]:
    """获取commit的详细信息"""
    try:
        cmd = [
            "gh", "api",
            f"/repos/{repo}/commits/{sha}"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            return json.loads(result.stdout)

    except Exception as e:
        print(f"  获取commit详情失败: {e}")

    return None


def extract_functions_from_diff(diff_text: str, language: str) -> List[str]:
    """从diff中提取函数级代码"""
    functions = []

    # 简单的函数提取逻辑
    if language.lower() in ['c++', 'c', 'cpp']:
        # C++函数模式
        pattern = r'^\+.*?(?:void|int|bool|float|double|char|auto)\s+\w+\s*\([^)]*\)\s*\{[\s\S]*?\n\+\}'
        matches = re.finditer(pattern, diff_text, re.MULTILINE)
        for match in matches:
            func = match.group(0)
            # 移除diff标记
            func = '\n'.join(line[1:] if line.startswith('+') else line
                           for line in func.split('\n'))
            if len(func.split('\n')) >= 5:  # 至少5行
                functions.append(func)

    elif language.lower() in ['python', 'py']:
        # Python函数模式
        pattern = r'^\+\s*def\s+\w+\s*\([^)]*\):[\s\S]*?(?=\n\+\s*(?:def|class|\Z))'
        matches = re.finditer(pattern, diff_text, re.MULTILINE)
        for match in matches:
            func = match.group(0)
            func = '\n'.join(line[1:] if line.startswith('+') else line
                           for line in func.split('\n'))
            if len(func.split('\n')) >= 5:
                functions.append(func)

    return functions


def infer_cwe_from_message(message: str) -> Optional[str]:
    """从commit message推断CWE类型"""
    message_lower = message.lower()

    # CWE关键词映射
    cwe_keywords = {
        'CWE-119': ['buffer overflow', 'buffer overrun', 'strcpy', 'sprintf'],
        'CWE-78': ['command injection', 'os.system', 'shell injection'],
        'CWE-401': ['memory leak', 'resource leak', 'not freed'],
        'CWE-476': ['null pointer', 'nullptr', 'null dereference'],
        'CWE-362': ['race condition', 'thread safe', 'concurrent'],
        'CWE-416': ['use after free', 'dangling pointer'],
        'CWE-190': ['integer overflow', 'integer underflow'],
        'CWE-134': ['format string', 'printf'],
        'CWE-667': ['lock', 'mutex', 'deadlock'],
        'CWE-404': ['resource not released', 'file not closed'],
        'CWE-665': ['initialization', 'uninitialized'],
        'CWE-754': ['exception', 'error handling', 'check'],
    }

    for cwe, keywords in cwe_keywords.items():
        if any(kw in message_lower for kw in keywords):
            return cwe

    return None


def main():
    print("=" * 70)
    print("GitHub机器人安全漏洞数据收集")
    print("=" * 70)

    output_file = Path("data/github_collected_samples.jsonl")
    output_file.parent.mkdir(parents=True, exist_ok=True)

    collected_samples = []

    # 遍历目标仓库
    for repo in ROBOT_REPOS[:5]:  # 先测试前5个仓库
        print(f"\n{'='*70}")
        print(f"处理仓库: {repo}")
        print(f"{'='*70}")

        # 搜索安全相关commit
        commit_shas = search_github_commits(repo, SECURITY_KEYWORDS, max_results=20)

        print(f"找到 {len(commit_shas)} 个候选commit")

        # 处理每个commit
        for i, sha in enumerate(commit_shas[:10], 1):  # 每个仓库最多10个commit
            print(f"\n[{i}/{min(10, len(commit_shas))}] 处理commit: {sha[:8]}")

            commit_data = get_commit_details(repo, sha)
            if not commit_data:
                continue

            message = commit_data.get('commit', {}).get('message', '')
            print(f"  消息: {message[:60]}...")

            # 推断CWE类型
            cwe = infer_cwe_from_message(message)
            if cwe:
                print(f"  推断CWE: {cwe}")

            # 获取diff
            files = commit_data.get('files', [])
            for file_data in files[:3]:  # 每个commit最多3个文件
                filename = file_data.get('filename', '')

                # 判断语言
                if filename.endswith(('.cpp', '.cc', '.c', '.h', '.hpp')):
                    language = 'C++'
                elif filename.endswith('.py'):
                    language = 'Python'
                else:
                    continue

                print(f"    文件: {filename} ({language})")

                # 提取函数（这里简化处理，实际需要更复杂的逻辑）
                patch = file_data.get('patch', '')
                if not patch:
                    continue

                # 简单提取：取patch中的代码片段
                # 实际应该用更复杂的AST解析
                lines = [l for l in patch.split('\n') if l.startswith('+') and not l.startswith('+++')]
                code = '\n'.join(l[1:] for l in lines)

                if len(code.strip().split('\n')) < 5:
                    continue

                sample = {
                    'id': f"{repo.replace('/', '_')}_{cwe or 'unknown'}_{sha[:8]}",
                    'repo': repo,
                    'commit_sha': sha,
                    'cwe_id': cwe,
                    'cwe_name': None,  # 需要后续填充
                    'language': language,
                    'vulnerable_code': code[:1000],  # 限制长度
                    'label': 1 if cwe else 0,
                    'severity': 'MEDIUM',  # 默认中等
                    'description': message[:200],
                    'source': 'github_collected'
                }

                collected_samples.append(sample)
                print(f"      ✓ 收集样本: {len(code.split())} 行")

            time.sleep(2)  # 避免API限制

    # 保存结果
    print(f"\n{'='*70}")
    print(f"收集完成！")
    print(f"总样本数: {len(collected_samples)}")
    print(f"{'='*70}")

    with open(output_file, 'w') as f:
        for sample in collected_samples:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')

    print(f"\n已保存到: {output_file}")

    # 统计
    cwe_counts = {}
    for sample in collected_samples:
        cwe = sample.get('cwe_id', 'unknown')
        cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

    print(f"\nCWE分布:")
    for cwe, count in sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {cwe}: {count}")


if __name__ == "__main__":
    main()
