#!/usr/bin/env python3
"""
Step 4: 合并 CVE路 + commit路 数据，去重、清洗、按仓库切分。
输出：
  data_v2/processed/train_v2.jsonl
  data_v2/processed/test_v2.jsonl
  data_v2/processed/rag_corpus_v2.jsonl
"""

import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
CVE_PAIRS = ROOT / "data_v2" / "raw" / "cve_pairs.jsonl"
COMMIT_PAIRS = ROOT / "data_v2" / "raw" / "commit_pairs.jsonl"
OUT_DIR = ROOT / "data_v2" / "processed"
OUT_DIR.mkdir(parents=True, exist_ok=True)

random.seed(42)

# 目标 CWE 白名单
TARGET_CWES = {
    "CWE-119", "CWE-401", "CWE-362", "CWE-476",
    "CWE-416", "CWE-190", "CWE-134", "CWE-78"
}


def code_hash(code: str) -> str:
    return hashlib.md5(code.strip().encode("utf-8")).hexdigest()


def is_valid(sample: dict) -> bool:
    code = sample.get("vulnerable_code", "")
    if not code:
        return False
    lines = [l for l in code.split("\n") if l.strip()]
    return 8 <= len(lines) <= 80


def load_jsonl(path: Path):
    if not path.exists():
        print(f"  [경고] {path} 없음, 스킵")
        return []
    data = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                data.append(json.loads(line))
    return data


def save_jsonl(data, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for item in data:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    print(f"  저장: {path} ({len(data)}条)")


def main():
    # 1. 加载两路数据
    cve_data = load_jsonl(CVE_PAIRS)
    commit_data = load_jsonl(COMMIT_PAIRS)
    print(f"CVE路: {len(cve_data)} 条")
    print(f"commit路: {len(commit_data)} 条")

    all_data = cve_data + commit_data
    print(f"合并后: {len(all_data)} 条")

    # 2. 质量过滤
    all_data = [s for s in all_data if is_valid(s)]
    print(f"质量过滤后: {len(all_data)} 条")

    # 3. 代码哈希去重
    seen_hashes = set()
    deduped = []
    for s in all_data:
        h = code_hash(s.get("vulnerable_code", ""))
        if h not in seen_hashes:
            seen_hashes.add(h)
            deduped.append(s)
    print(f"去重后: {len(deduped)} 条")

    # 过滤非机器人相关仓库
    EXCLUDE_REPOS = {
        "torvalds/linux",
        "jxxghp/MoviePilot",
        "arduino/ArduinoCore-avr",
    }
    deduped = [s for s in deduped if s.get("repo") not in EXCLUDE_REPOS]
    print(f"过滤无关仓库后: {len(deduped)} 条")

    # 4. 按仓库分组
    by_repo = defaultdict(list)
    for s in deduped:
        by_repo[s["repo"]].append(s)

    repos = list(by_repo.keys())
    print(f"仓库数: {len(repos)}")

    # 5. 按仓库切分 train/test（6:4，让测试集更充足）
    random.shuffle(repos)
    split = int(len(repos) * 0.6)
    train_repos = set(repos[:split])
    test_repos = set(repos[split:])

    train_data = [s for s in deduped if s["repo"] in train_repos]
    test_data = [s for s in deduped if s["repo"] in test_repos]
    print(f"训练集仓库: {len(train_repos)}，样本: {len(train_data)}")
    print(f"测试集仓库: {len(test_repos)}，样本: {len(test_data)}")

    # 6. RAG 语料 = 训练集中 label=1 的样本（漏洞样本）
    rag_corpus = [s for s in train_data if s["label"] == 1]
    print(f"RAG语料(训练集漏洞样本): {len(rag_corpus)} 条")

    # 7. 统计
    def stats(data, name):
        l1 = sum(1 for s in data if s["label"] == 1)
        l0 = sum(1 for s in data if s["label"] == 0)
        cwe_dist = defaultdict(int)
        for s in data:
            cwe_dist[str(s.get("cwe_id", "None"))] += 1
        print(f"\n{name}: 总={len(data)}, 漏洞={l1}, 干净={l0}")
        print(f"  CWE分布: {dict(sorted(cwe_dist.items()))}")

    stats(train_data, "训练集")
    stats(test_data, "测试集")
    stats(rag_corpus, "RAG语料")

    # 8. 独立性验证
    train_ids = {s["id"] for s in train_data}
    test_ids = {s["id"] for s in test_data}
    train_hashes = {code_hash(s["vulnerable_code"]) for s in train_data}
    test_hashes = {code_hash(s["vulnerable_code"]) for s in test_data}
    rag_hashes = {code_hash(s["vulnerable_code"]) for s in rag_corpus}

    id_overlap = train_ids & test_ids
    hash_overlap = train_hashes & test_hashes
    rag_test_overlap = rag_hashes & test_hashes

    print(f"\n独立性验证:")
    print(f"  ID重叠: {len(id_overlap)}")
    print(f"  代码哈希重叠(train/test): {len(hash_overlap)}")
    print(f"  RAG/test代码哈希重叠: {len(rag_test_overlap)}")

    if hash_overlap or rag_test_overlap:
        print("  [警告] 存在重叠，自动清理...")
        test_data = [s for s in test_data if code_hash(s["vulnerable_code"]) not in rag_hashes]
        print(f"  清理后测试集: {len(test_data)} 条")

    # 9. 保存
    save_jsonl(train_data, OUT_DIR / "train_v2.jsonl")
    save_jsonl(test_data, OUT_DIR / "test_v2.jsonl")
    save_jsonl(rag_corpus, OUT_DIR / "rag_corpus_v2.jsonl")

    # 保存仓库切分记录
    split_record = {
        "train_repos": sorted(train_repos),
        "test_repos": sorted(test_repos),
    }
    (OUT_DIR / "repo_split.json").write_text(
        json.dumps(split_record, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"\n完成！结果保存在 {OUT_DIR}")


if __name__ == "__main__":
    main()
