# [可视化] 读取experiments/ablation/结果，生成F1柱状图/混淆矩阵网格/Per-CWE召回热图，用于论文图表
#!/usr/bin/env python3
"""D4: Visualize ablation results.

Generates 3 plots from experiments/ablation/*.json:
1. F1 progression bar chart (incremental contribution)
2. Confusion matrices for each config
3. Per-CWE recall heatmap

Usage:
    python scripts/plot_results.py
"""

import argparse
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent


CONFIG_LABELS = {
    "1_naive": "Naive LLM",
    "2_rag_basic": "+ RAG (Dense)",
    "3_hybrid": "+ Hybrid (BM25)",
    "4_hybrid_hyde": "+ HyDE",
    "5_hybrid_hyde_rerank": "+ Reranker",
    "6_hybrid_hyde_rerank_crag": "+ CRAG",
    "7_full_no_verifier": "+ Router (Full)",
    "8_full_with_voting": "+ Voting",
    "9_full_with_debate": "+ Debate",
    "10_full_with_verifier": "+ Verifier",
}


def load_ablation_results():
    """Load all ablation result files."""
    ablation_dir = ROOT / "experiments" / "ablation"
    if not ablation_dir.exists():
        print(f"ERROR: {ablation_dir} not found. Run run_ablation.py first.")
        sys.exit(1)

    results = {}
    for path in sorted(ablation_dir.glob("[0-9]*.json")):
        name = path.stem
        if name == "ablation_summary":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if "metrics" in data:
                results[name] = data
        except Exception as e:
            print(f"  WARN: failed to load {path.name}: {e}")
    return results


def plot_f1_progression(results, out_path):
    """Bar chart showing F1 / Precision / Recall progression."""
    names = [n for n in CONFIG_LABELS.keys() if n in results]
    if not names:
        print("  No results to plot")
        return

    labels = [CONFIG_LABELS[n] for n in names]
    f1s = [results[n]["metrics"]["f1"] for n in names]
    precisions = [results[n]["metrics"]["precision"] for n in names]
    recalls = [results[n]["metrics"]["recall"] for n in names]

    x = np.arange(len(labels))
    width = 0.27

    fig, ax = plt.subplots(figsize=(13, 6))
    bars_p = ax.bar(x - width, precisions, width, label="Precision", color="#5DADE2")
    bars_r = ax.bar(x, recalls, width, label="Recall", color="#F5B041")
    bars_f = ax.bar(x + width, f1s, width, label="F1", color="#58D68D")

    ax.set_ylabel("Score", fontsize=12)
    ax.set_title("Ablation Study: Component Contribution to Detection Performance", fontsize=13)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=10)
    ax.legend(fontsize=11)
    ax.grid(axis="y", alpha=0.3)
    ax.set_ylim(0, 1.05)

    for bars in [bars_p, bars_r, bars_f]:
        for b in bars:
            h = b.get_height()
            ax.annotate(f"{h:.2f}", xy=(b.get_x() + b.get_width() / 2, h),
                        xytext=(0, 2), textcoords="offset points",
                        ha="center", va="bottom", fontsize=8)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"  Saved: {out_path}")


def plot_confusion_matrices(results, out_path):
    """Grid of confusion matrices, one per config."""
    names = [n for n in CONFIG_LABELS.keys() if n in results]
    n = len(names)
    if n == 0:
        return

    cols = min(4, n)
    rows = (n + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(cols * 3.2, rows * 3.0))
    axes = np.array(axes).reshape(-1)

    for i, name in enumerate(names):
        m = results[name]["metrics"]
        cm = np.array([
            [m["tn"], m["fp"]],
            [m["fn"], m["tp"]],
        ])
        ax = axes[i]
        im = ax.imshow(cm, cmap="Blues")
        ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
        ax.set_xticklabels(["clean", "vuln"])
        ax.set_yticklabels(["clean", "vuln"])
        ax.set_xlabel("Predicted")
        ax.set_ylabel("True")
        ax.set_title(CONFIG_LABELS[name], fontsize=10)

        for r in range(2):
            for c in range(2):
                ax.text(c, r, str(cm[r, c]), ha="center", va="center",
                        color="white" if cm[r, c] > cm.max() / 2 else "black",
                        fontsize=11, fontweight="bold")

    for j in range(n, len(axes)):
        axes[j].axis("off")

    plt.suptitle("Confusion Matrices Across Ablation Configurations", fontsize=12)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"  Saved: {out_path}")


def plot_cwe_recall_heatmap(results, out_path):
    """Per-CWE recall across configurations."""
    names = [n for n in CONFIG_LABELS.keys() if n in results and "cwe_recall" in results[n]]
    if not names:
        return

    all_cwes = set()
    for n in names:
        all_cwes.update(results[n]["cwe_recall"].keys())
    cwes = sorted(all_cwes)
    if not cwes:
        return

    matrix = np.zeros((len(names), len(cwes)))
    for i, n in enumerate(names):
        d = results[n]["cwe_recall"]
        for j, cwe in enumerate(cwes):
            matrix[i, j] = d.get(cwe, {}).get("recall", 0)

    fig, ax = plt.subplots(figsize=(max(8, len(cwes) * 1.0), max(4, len(names) * 0.5)))
    im = ax.imshow(matrix, cmap="YlGn", aspect="auto", vmin=0, vmax=1)

    ax.set_xticks(range(len(cwes)))
    ax.set_xticklabels(cwes, rotation=30, ha="right")
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels([CONFIG_LABELS[n] for n in names])

    for i in range(len(names)):
        for j in range(len(cwes)):
            ax.text(j, i, f"{matrix[i, j]:.2f}",
                    ha="center", va="center",
                    color="white" if matrix[i, j] > 0.5 else "black",
                    fontsize=8)

    plt.colorbar(im, ax=ax, label="Recall")
    ax.set_title("Per-CWE Recall Across Ablation Configurations")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"  Saved: {out_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=str, default="experiments/figures")
    args = parser.parse_args()

    out_dir = ROOT / args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Loading ablation results...")
    results = load_ablation_results()
    if not results:
        print("ERROR: No results found. Run run_ablation.py first.")
        return
    print(f"  Loaded {len(results)} configurations")

    print("\nGenerating plots...")
    plot_f1_progression(results, out_dir / "ablation_f1_progression.png")
    plot_confusion_matrices(results, out_dir / "ablation_confusion_matrices.png")
    plot_cwe_recall_heatmap(results, out_dir / "ablation_cwe_recall.png")

    print(f"\nAll figures saved to: {out_dir}")


if __name__ == "__main__":
    main()
