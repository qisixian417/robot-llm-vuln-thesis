#!/usr/bin/env python3
"""
数据集 v2 构建入口脚本
依次执行 step1 ~ step5，支持从任意步骤开始（断点续跑）

用法：
    python scripts/build_dataset_v2/build_all.py          # 从头开始
    python scripts/build_dataset_v2/build_all.py --from 3 # 从第3步开始
"""

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS = Path(__file__).resolve().parent

STEPS = [
    (1, "step1_fetch_cve.py",         "从 NVD 搜索机器人相关 CVE"),
    (2, "step2_extract_code_pairs.py", "从 CVE commit 提取成对代码"),
    (3, "step3_fetch_commit_pairs.py", "从 GitHub commit 关键词路提取成对代码"),
    (4, "step4_merge_and_split.py",    "合并去重清洗切分"),
    (5, "step5_label_cwe.py",          "LLM 补全 CWE 标签"),
]


def run_step(script: str, desc: str):
    print(f"\n{'='*60}")
    print(f"执行: {desc}")
    print(f"脚本: {script}")
    print('='*60)
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / script)],
        cwd=str(ROOT),
    )
    if result.returncode != 0:
        print(f"\n[错误] {script} 执行失败，退出码 {result.returncode}")
        print("请检查错误信息后，用 --from N 从该步骤重新开始")
        sys.exit(result.returncode)
    print(f"\n[完成] {desc}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--from", dest="from_step", type=int, default=1,
                        help="从第几步开始（默认1）")
    parser.add_argument("--only", type=int, default=None,
                        help="只运行某一步")
    args = parser.parse_args()

    steps_to_run = [
        (n, script, desc) for n, script, desc in STEPS
        if (args.only is None and n >= args.from_step) or n == args.only
    ]

    print(f"数据集 v2 构建流程")
    print(f"原始数据保留在 data/（不受影响）")
    print(f"新数据输出到 data_v2/")
    print(f"将执行 {len(steps_to_run)} 个步骤: {[n for n,_,_ in steps_to_run]}")

    for n, script, desc in steps_to_run:
        run_step(script, f"Step {n}: {desc}")

    print(f"\n{'='*60}")
    print("全部完成！")
    print(f"训练集: data_v2/processed/train_v2.jsonl")
    print(f"测试集: data_v2/processed/test_v2.jsonl")
    print(f"RAG语料: data_v2/processed/rag_corpus_v2.jsonl")
    print('='*60)


if __name__ == "__main__":
    main()
