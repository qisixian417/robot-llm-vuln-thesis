# [数据准备] 质量过滤：删除<3行/<50字符的代码片段，生成*_filtered.jsonl，减少标签噪声
#!/usr/bin/env python3
"""Dataset quality filter.

Removes samples that are too short to contain analyzable vulnerability patterns.
Keeps originals untouched; creates *_filtered.jsonl versions.

Filter: >= 3 meaningful (non-blank, non-comment) lines AND >= 50 total chars.

Rationale: a code fragment shorter than this threshold cannot exhibit
the structural patterns (allocation path, buffer ops, concurrency, etc.)
required for the 9 CWE types in this study.
"""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def meaningful_lines(code: str):
    return [
        l.strip() for l in code.splitlines()
        if l.strip()
        and not l.strip().startswith("//")
        and not l.strip().startswith("#")
        and not re.match(r"^\s*\*", l)
    ]


def passes_quality_filter(sample: dict) -> bool:
    code = sample.get("vulnerable_code", "") or sample.get("code", "")
    ml = meaningful_lines(code)
    return len(ml) >= 3 and len(code) >= 50


def filter_file(src: Path, dst: Path) -> dict:
    samples = []
    with open(src, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))

    kept = [s for s in samples if passes_quality_filter(s)]
    removed = [s for s in samples if not passes_quality_filter(s)]

    with open(dst, "w", encoding="utf-8") as f:
        for s in kept:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    stats = {
        "total_before": len(samples),
        "total_after": len(kept),
        "removed": len(removed),
        "vuln_before": sum(1 for s in samples if s.get("label") == 1),
        "vuln_after": sum(1 for s in kept if s.get("label") == 1),
        "removed_vuln": sum(1 for s in removed if s.get("label") == 1),
        "removed_clean": sum(1 for s in removed if s.get("label") == 0),
    }
    return stats


def main():
    files = [
        ("data/test_v2.jsonl",         "data/test_v2_filtered.jsonl"),
        ("data/train_v2.jsonl",        "data/train_v2_filtered.jsonl"),
        ("data/rag_corpus_v2.jsonl",   "data/rag_corpus_v2_filtered.jsonl"),
    ]

    print("Dataset Quality Filter")
    print("=" * 60)
    print("Criterion: >= 3 meaningful lines AND >= 50 total chars")
    print("=" * 60)

    for src_rel, dst_rel in files:
        src = ROOT / src_rel
        dst = ROOT / dst_rel
        if not src.exists():
            print(f"SKIP (not found): {src_rel}")
            continue

        stats = filter_file(src, dst)
        name = src.stem
        removed_pct = stats["removed"] / stats["total_before"] * 100
        vuln_ratio_before = stats["vuln_before"] / stats["total_before"] * 100 if stats["total_before"] else 0
        vuln_ratio_after = stats["vuln_after"] / stats["total_after"] * 100 if stats["total_after"] else 0

        print(f"\n[{name}]")
        print(f"  Before : {stats['total_before']:4d} samples  (vuln={stats['vuln_before']}, {vuln_ratio_before:.1f}%)")
        print(f"  After  : {stats['total_after']:4d} samples  (vuln={stats['vuln_after']}, {vuln_ratio_after:.1f}%)")
        print(f"  Removed: {stats['removed']:4d} ({removed_pct:.1f}%)  — vuln={stats['removed_vuln']}, clean={stats['removed_clean']}")
        print(f"  Saved  : {dst_rel}")

    print("\n" + "=" * 60)
    print("Originals preserved. Use *_filtered.jsonl for experiments.")
    print("Note: Rebuild Chroma after filtering with:")
    print("  python scripts/build_chroma_db.py --reset --corpus data/rag_corpus_v2_filtered.jsonl")
    print("=" * 60)


if __name__ == "__main__":
    main()
