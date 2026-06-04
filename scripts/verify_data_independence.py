# [数据质量] 三重验证：ID/代码哈希/仓库级检查测试集与RAG语料无重叠，确保实验无数据泄漏
#!/usr/bin/env python3
"""Verify data independence between test set and RAG corpus.

Checks for overlap using:
1. ID-based comparison
2. Code content hash (whitespace-normalized)
3. Repo-level leakage
"""

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_jsonl(filepath: Path) -> list:
    samples = []
    if not filepath.exists():
        print(f"ERROR: {filepath} not found")
        return samples
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def normalize_code(code: str) -> str:
    code = re.sub(r"//.*", "", code)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    code = re.sub(r"#.*", "", code)
    code = re.sub(r"\s+", "", code)
    return code.lower()


def code_hash(code: str) -> str:
    return hashlib.sha256(normalize_code(code).encode()).hexdigest()


def main():
    test_path = ROOT / "data" / "test_v2.jsonl"
    rag_path = ROOT / "data" / "rag_corpus_v2.jsonl"
    train_path = ROOT / "data" / "train_v2.jsonl"

    test_samples = load_jsonl(test_path)
    rag_samples = load_jsonl(rag_path)
    train_samples = load_jsonl(train_path)

    if not test_samples or not rag_samples:
        print("Cannot proceed: missing data files.")
        return

    print("=" * 70)
    print("DATA INDEPENDENCE VERIFICATION")
    print("=" * 70)

    # 1. ID overlap
    test_ids = set(s.get("id", "") for s in test_samples)
    rag_ids = set(s.get("id", "") for s in rag_samples)
    id_overlap = test_ids & rag_ids
    print(f"\n[1] ID-based overlap:")
    print(f"    Test IDs: {len(test_ids)}, RAG IDs: {len(rag_ids)}")
    print(f"    Overlap: {len(id_overlap)}")
    if id_overlap:
        print(f"    [FAIL] overlapping IDs: {list(id_overlap)[:5]}...")
    else:
        print(f"    [PASS]")

    # 2. Code content hash overlap
    test_hashes = {}
    for s in test_samples:
        code = s.get("vulnerable_code", "") or s.get("code", "")
        if code:
            test_hashes[code_hash(code)] = s.get("id", "?")

    rag_hashes = {}
    for s in rag_samples:
        code = s.get("vulnerable_code", "") or s.get("code", "") or s.get("content", "")
        if code:
            rag_hashes[code_hash(code)] = s.get("id", "?")

    hash_overlap = set(test_hashes.keys()) & set(rag_hashes.keys())
    print(f"\n[2] Code content hash overlap (whitespace-normalized):")
    print(f"    Test hashes: {len(test_hashes)}, RAG hashes: {len(rag_hashes)}")
    print(f"    Overlap: {len(hash_overlap)}")
    if hash_overlap:
        print(f"    [FAIL] duplicated code found:")
        for h in list(hash_overlap)[:3]:
            print(f"      test={test_hashes[h]}, rag={rag_hashes[h]}")
    else:
        print(f"    [PASS]")

    # 3. Repo-level leakage
    test_repos = set(s.get("repo", "") for s in test_samples) - {""}
    train_repos = set(s.get("repo", "") for s in train_samples) - {""}
    repo_overlap = test_repos & train_repos
    print(f"\n[3] Repo-level leakage:")
    print(f"    Test repos: {len(test_repos)}, Train repos: {len(train_repos)}")
    print(f"    Repos in both: {len(repo_overlap)}")
    if repo_overlap:
        print(f"    [FAIL] shared repos: {sorted(repo_overlap)[:5]}...")
    else:
        print(f"    [PASS]")

    # Summary
    all_pass = (len(id_overlap) == 0 and len(hash_overlap) == 0 and len(repo_overlap) == 0)
    print(f"\n{'=' * 70}")
    if all_pass:
        print("RESULT: ALL CHECKS PASSED - no data leakage detected")
    else:
        print("RESULT: LEAKAGE DETECTED - fix before running experiments")
    print("=" * 70)


if __name__ == "__main__":
    main()
