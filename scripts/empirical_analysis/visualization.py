# [实证分析] 可视化工具：violin图/热图/森林图/Lorenz曲线，生成论文图表
"""
可视化模块：生成论文级别的图表
"""
import numpy as np
import matplotlib
matplotlib.use('Agg')  # 非交互式后端
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from typing import Dict, List, Any

from .config import (
    FIGURES_DIR, COLORS, FIG_SINGLE_COL, FIG_DOUBLE_COL, FIG_SQUARE,
    setup_plot_style, CWE_TO_ROS_LAYER
)


def save_fig(fig, name: str):
    """保存图片（PDF + PNG）"""
    fig.savefig(FIGURES_DIR / f"{name}.pdf", format='pdf')
    fig.savefig(FIGURES_DIR / f"{name}.png", format='png')
    plt.close(fig)


# ============================================================================
# RQ1 可视化
# ============================================================================

def plot_rq1_pareto(rq1_results: Dict):
    """Pareto图：CWE分布 + 累积百分比"""
    setup_plot_style()
    dist = rq1_results["cwe_distribution"]
    # 排除unknown
    dist = [d for d in dist if d.get("cwe", d.get("cwe_id", "")) != "unknown"]

    labels = [d.get("cwe", d.get("cwe_id", "")) for d in dist]
    counts = [d["count"] for d in dist]
    total = sum(counts)
    cumulative = np.cumsum(counts) / total * 100

    fig, ax1 = plt.subplots(figsize=FIG_DOUBLE_COL)
    bars = ax1.bar(range(len(labels)), counts, color=COLORS["primary"], alpha=0.8)
    ax1.set_xlabel("CWE Type")
    ax1.set_ylabel("Count", color=COLORS["primary"])
    ax1.set_xticks(range(len(labels)))
    ax1.set_xticklabels(labels, rotation=45, ha='right', fontsize=8)

    ax2 = ax1.twinx()
    ax2.plot(range(len(labels)), cumulative, 'o-', color=COLORS["secondary"], linewidth=2)
    ax2.set_ylabel("Cumulative %", color=COLORS["secondary"])
    ax2.set_ylim(0, 105)
    ax2.axhline(y=80, color='gray', linestyle='--', alpha=0.5)

    fig.tight_layout()
    save_fig(fig, "rq1_pareto")


def plot_rq1_lorenz(rq1_results: Dict):
    """Lorenz曲线：漏洞集中度"""
    setup_plot_style()
    dist = rq1_results["cwe_distribution"]
    counts = sorted([d["count"] for d in dist if d.get("cwe", d.get("cwe_id", "")) != "unknown"])
    n = len(counts)
    total = sum(counts)

    # Lorenz curve points
    cum_share = np.concatenate([[0], np.cumsum(counts) / total])
    pop_share = np.linspace(0, 1, n + 1)

    fig, ax = plt.subplots(figsize=FIG_SINGLE_COL)
    ax.plot(pop_share, cum_share, 'b-', linewidth=2, label='Lorenz Curve')
    ax.plot([0, 1], [0, 1], 'k--', alpha=0.5, label='Perfect Equality')
    ax.fill_between(pop_share, cum_share, pop_share, alpha=0.1, color='blue')
    ax.set_xlabel("Cumulative Share of CWE Types")
    ax.set_ylabel("Cumulative Share of Vulnerabilities")
    ax.set_title(f"Lorenz Curve (Gini = {rq1_results.get('gini_coefficient', 0):.3f})")
    ax.legend(loc='upper left')
    fig.tight_layout()
    save_fig(fig, "rq1_lorenz")


# ============================================================================
# RQ2 可视化
# ============================================================================

def plot_rq2_component_density(rq2_results: Dict):
    """组件漏洞密度柱状图"""
    setup_plot_style()
    table = rq2_results["component_density_table"]
    table = sorted(table, key=lambda x: -x["density"])

    labels = [t["component"] for t in table]
    densities = [t["density"] for t in table]

    fig, ax = plt.subplots(figsize=FIG_DOUBLE_COL)
    colors = [COLORS["vulnerable"] if d > 0.5 else COLORS["primary"] for d in densities]
    ax.barh(range(len(labels)), densities, color=colors, alpha=0.8)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels)
    ax.set_xlabel("Vulnerability Density")
    ax.axvline(x=0.5, color='gray', linestyle='--', alpha=0.5)
    fig.tight_layout()
    save_fig(fig, "rq2_component_density")


def plot_rq2_forest(rq2_results: Dict):
    """Forest plot: 各组件Odds Ratio"""
    setup_plot_style()
    or_data = rq2_results.get("component_odds_ratios", {})
    if not or_data:
        return

    items = [(comp, data) for comp, data in or_data.items()
             if data.get("or_ci_lower") is not None]
    if not items:
        return

    items.sort(key=lambda x: x[1]["odds_ratio"])

    fig, ax = plt.subplots(figsize=(5, max(3, len(items) * 0.5)))
    for i, (comp, data) in enumerate(items):
        or_val = data["odds_ratio"]
        ci_low = data["or_ci_lower"]
        ci_high = min(data["or_ci_upper"], or_val * 5)  # cap for display
        color = COLORS["vulnerable"] if data.get("significant", False) else COLORS["primary"]
        ax.errorbar(or_val, i, xerr=[[or_val - ci_low], [ci_high - or_val]],
                    fmt='o', color=color, capsize=3, markersize=6)

    ax.axvline(x=1, color='gray', linestyle='--', alpha=0.7)
    ax.set_yticks(range(len(items)))
    ax.set_yticklabels([item[0] for item in items])
    ax.set_xlabel("Odds Ratio (95% CI)")
    ax.set_xscale('log')
    fig.tight_layout()
    save_fig(fig, "rq2_forest_plot")


# ============================================================================
# RQ3 可视化
# ============================================================================

def plot_rq3_violin(rq3_results: Dict, samples: List[Dict]):
    """Violin plots: 复杂度指标分布对比"""
    setup_plot_style()
    metrics = ["loc", "sloc", "num_functions_called", "max_nesting_depth",
               "num_conditions", "cyclomatic_complexity", "num_pointers"]

    fig, axes = plt.subplots(2, 4, figsize=(12, 6))
    axes = axes.flatten()

    for i, metric in enumerate(metrics):
        if i >= len(axes):
            break
        vuln_vals = [s["_metrics"][metric] for s in samples if s["_label"] == 1]
        benign_vals = [s["_metrics"][metric] for s in samples if s["_label"] == 0]

        data = vuln_vals + benign_vals
        labels = ["Vuln"] * len(vuln_vals) + ["Benign"] * len(benign_vals)

        ax = axes[i]
        parts = ax.violinplot([vuln_vals, benign_vals], positions=[0, 1], showmedians=True)
        for pc in parts['bodies']:
            pc.set_alpha(0.6)
        ax.set_xticks([0, 1])
        ax.set_xticklabels(["Vuln", "Benign"])
        ax.set_title(metric, fontsize=9)

    # 隐藏多余的subplot
    if len(metrics) < len(axes):
        for j in range(len(metrics), len(axes)):
            axes[j].set_visible(False)

    fig.suptitle("Code Complexity Metrics: Vulnerable vs Benign", fontsize=11)
    fig.tight_layout()
    save_fig(fig, "rq3_violin_plots")


def plot_rq3_correlation_heatmap(rq3_results: Dict):
    """Spearman相关矩阵热力图"""
    setup_plot_style()
    corr_data = rq3_results.get("spearman_correlation", {})
    if not corr_data or "matrix" not in corr_data:
        return

    matrix = np.array(corr_data["matrix"])
    labels = corr_data["metric_names"]

    fig, ax = plt.subplots(figsize=FIG_SQUARE)
    im = ax.imshow(matrix, cmap='RdBu_r', vmin=-1, vmax=1, aspect='auto')
    ax.set_xticks(range(len(labels)))
    ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=7)
    ax.set_yticklabels(labels, fontsize=7)

    # 添加数值标注
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, f"{matrix[i,j]:.2f}", ha='center', va='center', fontsize=6)

    fig.colorbar(im, ax=ax, shrink=0.8)
    ax.set_title("Spearman Correlation Matrix")
    fig.tight_layout()
    save_fig(fig, "rq3_correlation_heatmap")


# ============================================================================
# RQ5 可视化
# ============================================================================

def plot_rq5_pmi_heatmap(rq5_results: Dict):
    """PMI热力图：API特征 × CWE"""
    setup_plot_style()
    pmi_data = rq5_results.get("pmi_matrix", {})
    if not pmi_data or not isinstance(pmi_data, dict):
        return

    # pmi_matrix is {feature: {cwe: pmi_value}}
    features = sorted(pmi_data.keys())
    # Collect all CWEs
    all_cwes = set()
    for feat_data in pmi_data.values():
        if isinstance(feat_data, dict):
            all_cwes.update(feat_data.keys())
    cwes = sorted(all_cwes)

    if not features or not cwes:
        return

    matrix = np.zeros((len(features), len(cwes)))
    for i, feat in enumerate(features):
        feat_data = pmi_data.get(feat, {})
        if isinstance(feat_data, dict):
            for j, cwe in enumerate(cwes):
                matrix[i, j] = feat_data.get(cwe, 0)

    fig, ax = plt.subplots(figsize=(8, 5))
    im = ax.imshow(matrix, cmap='RdYlBu_r', aspect='auto')
    ax.set_xticks(range(len(cwes)))
    ax.set_yticks(range(len(features)))
    ax.set_xticklabels(cwes, rotation=45, ha='right', fontsize=7)
    ax.set_yticklabels(features, fontsize=8)
    ax.set_xlabel("CWE Type")
    ax.set_ylabel("ROS API Feature")
    fig.colorbar(im, ax=ax, label="PMI")
    ax.set_title("Pointwise Mutual Information: API Feature × CWE")
    fig.tight_layout()
    save_fig(fig, "rq5_pmi_heatmap")


def plot_rq5_forest(rq5_results: Dict):
    """Forest plot: API特征Odds Ratio"""
    setup_plot_style()
    # Try different key names
    feature_tests = rq5_results.get("feature_fisher_tests", {}) or rq5_results.get("fisher_tests", {})
    if not feature_tests or not isinstance(feature_tests, dict):
        return

    items = [(feat, data) for feat, data in feature_tests.items()
             if isinstance(data, dict) and data.get("or_ci_lower") is not None]
    items.sort(key=lambda x: x[1].get("odds_ratio", 1))

    if not items:
        return

    fig, ax = plt.subplots(figsize=(5, max(3, len(items) * 0.4)))
    for i, (feat, data) in enumerate(items):
        or_val = data.get("odds_ratio", 1)
        ci_low = data.get("or_ci_lower", or_val)
        ci_high = min(data.get("or_ci_upper", or_val), or_val * 10)
        sig = data.get("significant_fdr", data.get("significant", False))
        color = COLORS["vulnerable"] if sig else COLORS["primary"]
        # Ensure non-negative xerr
        xerr_low = max(0, or_val - ci_low)
        xerr_high = max(0, ci_high - or_val)
        ax.errorbar(or_val, i, xerr=[[xerr_low], [xerr_high]],
                    fmt='o', color=color, capsize=3, markersize=5)

    ax.axvline(x=1, color='gray', linestyle='--', alpha=0.7)
    ax.set_yticks(range(len(items)))
    ax.set_yticklabels([item[0] for item in items], fontsize=8)
    ax.set_xlabel("Odds Ratio (95% CI)")
    ax.set_xscale('log')
    ax.set_title("ROS API Feature Association with Vulnerability")
    fig.tight_layout()
    save_fig(fig, "rq5_forest_plot")


# ============================================================================
# RQ6 可视化
# ============================================================================

def plot_rq6_antipattern_heatmap(rq6_results: Dict):
    """热力图：反模式 × CWE"""
    setup_plot_style()
    contingency = rq6_results.get("antipattern_cwe_contingency", {}) or rq6_results.get("pattern_cwe_contingency", {})
    if not contingency:
        return

    patterns = contingency.get("patterns", contingency.get("row_labels", []))
    cwes = contingency.get("cwes", contingency.get("col_labels", []))
    matrix_data = contingency.get("matrix", contingency.get("table", []))
    matrix = np.array(matrix_data)

    if matrix.size == 0 or not patterns or not cwes:
        return

    fig, ax = plt.subplots(figsize=(7, 4))
    im = ax.imshow(matrix, cmap='YlOrRd', aspect='auto')
    ax.set_xticks(range(len(cwes)))
    ax.set_yticks(range(len(patterns)))
    ax.set_xticklabels(cwes, rotation=45, ha='right', fontsize=7)
    ax.set_yticklabels(patterns, fontsize=8)

    for i in range(min(len(patterns), matrix.shape[0])):
        for j in range(min(len(cwes), matrix.shape[1])):
            val = matrix[i, j]
            if val > 0:
                ax.text(j, i, str(int(val)), ha='center', va='center', fontsize=7)

    fig.colorbar(im, ax=ax, label="Count")
    ax.set_title("Anti-pattern × CWE Type Distribution")
    fig.tight_layout()
    save_fig(fig, "rq6_antipattern_heatmap")


# ============================================================================
# RQ8 可视化
# ============================================================================

def plot_rq8_repo_treemap(rq8_results: Dict):
    """Top仓库漏洞分布柱状图（替代treemap，无需额外依赖）"""
    setup_plot_style()
    top_repos = rq8_results.get("top_repos", rq8_results.get("top_10_repos", []))[:10]
    if not top_repos:
        return

    labels = [r.get("repo", r.get("name", "?")) for r in top_repos]
    counts = [r.get("vulnerable", r.get("vuln_count", 0)) for r in top_repos]
    densities = [r.get("density", r.get("vuln_density", 0)) for r in top_repos]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))

    # 漏洞数量
    ax1.barh(range(len(labels)), counts, color=COLORS["primary"], alpha=0.8)
    ax1.set_yticks(range(len(labels)))
    ax1.set_yticklabels(labels, fontsize=8)
    ax1.set_xlabel("Vulnerability Count")
    ax1.set_title("Top 10 Repos by Vulnerability Count")

    # 漏洞密度
    colors = [COLORS["vulnerable"] if d > 0.6 else COLORS["primary"] for d in densities]
    ax2.barh(range(len(labels)), densities, color=colors, alpha=0.8)
    ax2.set_yticks(range(len(labels)))
    ax2.set_yticklabels(labels, fontsize=8)
    ax2.set_xlabel("Vulnerability Density")
    ax2.set_title("Top 10 Repos by Density")
    ax2.axvline(x=0.5, color='gray', linestyle='--', alpha=0.5)

    fig.tight_layout()
    save_fig(fig, "rq8_repo_distribution")


# ============================================================================
# RQ10 可视化
# ============================================================================

def plot_rq10_feature_importance(rq10_results: Dict):
    """特征重要性对比图"""
    setup_plot_style()
    lr_features = rq10_results.get("feature_importance_logistic", [])[:10]
    rf_features = rq10_results.get("feature_importance_random_forest", [])[:10]

    if not lr_features or not rf_features:
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))

    # Logistic Regression
    names_lr = [f[0] for f in lr_features]
    vals_lr = [abs(f[1]) for f in lr_features]
    ax1.barh(range(len(names_lr)), vals_lr, color=COLORS["primary"], alpha=0.8)
    ax1.set_yticks(range(len(names_lr)))
    ax1.set_yticklabels(names_lr, fontsize=7)
    ax1.set_xlabel("|Coefficient|")
    ax1.set_title("Logistic Regression")

    # Random Forest
    names_rf = [f[0] for f in rf_features]
    vals_rf = [f[1] for f in rf_features]
    ax2.barh(range(len(names_rf)), vals_rf, color=COLORS["secondary"], alpha=0.8)
    ax2.set_yticks(range(len(names_rf)))
    ax2.set_yticklabels(names_rf, fontsize=7)
    ax2.set_xlabel("Gini Importance")
    ax2.set_title("Random Forest")

    fig.suptitle("Feature Importance Comparison", fontsize=11)
    fig.tight_layout()
    save_fig(fig, "rq10_feature_importance")


def plot_rq10_model_comparison(rq10_results: Dict):
    """模型AUC对比图"""
    setup_plot_style()
    nested = rq10_results.get("nested_model_comparison", {})
    if not nested:
        return

    models = ["Complexity\nOnly", "Complexity\n+ API", "Full\nModel"]
    aucs = [
        nested.get("complexity_only", {}).get("auc_mean", 0),
        nested.get("complexity_plus_api", {}).get("auc_mean", 0),
        nested.get("full_model", {}).get("auc_mean", 0),
    ]
    stds = [
        nested.get("complexity_only", {}).get("auc_std", 0),
        nested.get("complexity_plus_api", {}).get("auc_std", 0),
        nested.get("full_model", {}).get("auc_std", 0),
    ]

    # Add RF
    rf_auc = rq10_results.get("random_forest_auc", {})
    if rf_auc:
        models.append("Random\nForest")
        aucs.append(rf_auc.get("mean", 0))
        stds.append(rf_auc.get("std", 0))

    fig, ax = plt.subplots(figsize=FIG_SINGLE_COL)
    bars = ax.bar(range(len(models)), aucs, yerr=stds, capsize=4,
                  color=[COLORS["primary"]] * 3 + [COLORS["secondary"]], alpha=0.8)
    ax.set_xticks(range(len(models)))
    ax.set_xticklabels(models, fontsize=8)
    ax.set_ylabel("AUC (5-fold CV)")
    ax.set_ylim(0.4, 1.0)
    ax.axhline(y=0.5, color='gray', linestyle='--', alpha=0.5, label='Random')
    ax.legend()
    ax.set_title("Model Comparison")
    fig.tight_layout()
    save_fig(fig, "rq10_model_comparison")


# ============================================================================
# 主可视化函数
# ============================================================================

def generate_all_figures(results: Dict, samples: List[Dict]):
    """生成所有图表"""
    print("  生成RQ1图表...")
    if "rq1" in results:
        plot_rq1_pareto(results["rq1"])
        plot_rq1_lorenz(results["rq1"])

    print("  生成RQ2图表...")
    if "rq2" in results:
        plot_rq2_component_density(results["rq2"])
        plot_rq2_forest(results["rq2"])

    print("  生成RQ3图表...")
    if "rq3" in results:
        plot_rq3_violin(results["rq3"], samples)
        plot_rq3_correlation_heatmap(results["rq3"])

    print("  生成RQ5图表...")
    if "rq5" in results:
        plot_rq5_pmi_heatmap(results["rq5"])
        plot_rq5_forest(results["rq5"])

    print("  生成RQ6图表...")
    if "rq6" in results:
        plot_rq6_antipattern_heatmap(results["rq6"])

    print("  生成RQ8图表...")
    if "rq8" in results:
        plot_rq8_repo_treemap(results["rq8"])

    print("  生成RQ10图表...")
    if "rq10" in results:
        plot_rq10_feature_importance(results["rq10"])
        plot_rq10_model_comparison(results["rq10"])

    print(f"  所有图表已保存到: {FIGURES_DIR}")
