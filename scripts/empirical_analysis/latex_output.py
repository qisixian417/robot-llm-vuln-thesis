# [实证分析] LaTeX表格生成：将统计结果输出为论文可用的.tex格式
"""
LaTeX表格生成模块
"""
from typing import Dict, List, Any
from pathlib import Path

from .config import OUTPUT_DIR


def generate_all_latex_tables(results: Dict) -> str:
    """生成所有LaTeX表格，返回完整LaTeX内容"""
    lines = [
        "% ROS安全漏洞实证研究 v3 LaTeX表格",
        "% 自动生成，可直接插入论文",
        "% 需要 booktabs 宏包: \\usepackage{booktabs}",
        "",
    ]

    # Table 1: 数据集概览
    lines.extend(_table_dataset_overview(results))
    lines.append("")

    # Table 2: CWE分布（含Bootstrap CI）
    lines.extend(_table_cwe_distribution(results))
    lines.append("")

    # Table 3: 组件漏洞密度（含OR）
    lines.extend(_table_component_density(results))
    lines.append("")

    # Table 4: 复杂度指标对比
    lines.extend(_table_complexity_comparison(results))
    lines.append("")

    # Table 5: 语言对比
    lines.extend(_table_language_comparison(results))
    lines.append("")

    # Table 6: API特征关联
    lines.extend(_table_api_features(results))
    lines.append("")

    # Table 7: 代码反模式
    lines.extend(_table_antipatterns(results))
    lines.append("")

    # Table 8: 预测模型对比
    lines.extend(_table_model_comparison(results))

    return "\n".join(lines)


def _table_dataset_overview(results: Dict) -> List[str]:
    """Table 1: 数据集概览"""
    rq1 = results.get("rq1", {})
    rq4 = results.get("rq4", {})

    lines = [
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{ROS安全漏洞数据集概览}",
        "\\label{tab:dataset_overview}",
        "\\begin{tabular}{lr}",
        "\\toprule",
        "指标 & 数值 \\\\",
        "\\midrule",
        f"总样本数 & {rq1.get('total_vulnerable', 0) + results.get('dataset_summary', {}).get('benign', 0)} \\\\",
        f"漏洞样本 & {rq1.get('total_vulnerable', 0)} \\\\",
        f"良性样本 & {results.get('dataset_summary', {}).get('benign', 0)} \\\\",
        f"CWE类型数 & {rq1.get('num_cwe_types', 0)} \\\\",
        f"Shannon熵 & {rq1.get('shannon_entropy', 0):.3f} \\\\",
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
    ]
    return lines


def _table_cwe_distribution(results: Dict) -> List[str]:
    """Table 2: CWE分布"""
    rq1 = results.get("rq1", {})
    dist = rq1.get("cwe_distribution", [])
    ci_data = rq1.get("cwe_proportion_ci", {})

    lines = [
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{ROS安全漏洞CWE类型分布}",
        "\\label{tab:cwe_distribution}",
        "\\begin{tabular}{lrrrr}",
        "\\toprule",
        "CWE类型 & 数量 & 占比(\\%) & 95\\% CI & Top 25排名 \\\\",
        "\\midrule",
    ]

    for row in dist:
        cwe_id = row.get("cwe", "unknown")
        if cwe_id == "unknown":
            continue
        ci = ci_data.get(cwe_id, {})
        ci_str = f"[{ci.get('ci_lower', 0)*100:.1f}, {ci.get('ci_upper', 0)*100:.1f}]" if ci else "-"
        rank = row.get("top25_rank", "N/A")
        lines.append(
            f"{cwe_id} & {row['count']} & {row['percentage']:.1f} & {ci_str} & {rank} \\\\"
        )

    lines.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
    ])
    return lines


def _table_component_density(results: Dict) -> List[str]:
    """Table 3: 组件漏洞密度"""
    rq2 = results.get("rq2", {})
    table = rq2.get("component_density_table", [])

    lines = [
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{ROS组件漏洞密度与风险分析}",
        "\\label{tab:component_density}",
        "\\begin{tabular}{lrrrl}",
        "\\toprule",
        "组件 & 总数 & 漏洞数 & 密度 & 主要CWE \\\\",
        "\\midrule",
    ]

    for row in sorted(table, key=lambda x: -x.get("density", 0)):
        lines.append(
            f"{row['component']} & {row['total']} & {row['vulnerable']} & "
            f"{row['density']:.3f} & {row.get('top_cwe', '-')} \\\\"
        )

    lines.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
    ])
    return lines


def _table_complexity_comparison(results: Dict) -> List[str]:
    """Table 4: 复杂度指标对比"""
    rq3 = results.get("rq3", {})
    comparisons = rq3.get("metric_comparisons", {})

    lines = [
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{代码复杂度指标对比（漏洞 vs 良性）}",
        "\\label{tab:complexity}",
        "\\begin{tabular}{lrrrrrl}",
        "\\toprule",
        "指标 & 漏洞中位数 & 良性中位数 & $p$值 & $p_{adj}$ & Cliff's $\\delta$ & 效应 \\\\",
        "\\midrule",
    ]

    for metric, data in comparisons.items():
        v_med = data.get("vulnerable", {}).get("median", 0)
        b_med = data.get("benign", {}).get("median", 0)
        mw = data.get("mann_whitney", {})
        p_val = mw.get("p_value", 1)
        p_adj = mw.get("p_adjusted", 1)
        cd = data.get("cliff_delta", {})
        cd_val = cd.get("value", 0)
        cd_interp = cd.get("interpretation", "-")

        p_str = f"{p_val:.4f}" if p_val >= 0.0001 else "$<$0.0001"
        p_adj_str = f"{p_adj:.4f}" if p_adj >= 0.0001 else "$<$0.0001"
        sig_mark = "*" if mw.get("significant_adjusted", False) else ""

        lines.append(
            f"{metric} & {v_med:.1f} & {b_med:.1f} & {p_str} & "
            f"{p_adj_str}{sig_mark} & {cd_val:.3f} & {cd_interp} \\\\"
        )

    lines.extend([
        "\\bottomrule",
        "\\multicolumn{7}{l}{\\footnotesize * 经Holm-Bonferroni校正后显著 ($p_{adj} < 0.05$)} \\\\",
        "\\end{tabular}",
        "\\end{table}",
    ])
    return lines


def _table_language_comparison(results: Dict) -> List[str]:
    """Table 5: 语言对比"""
    rq4 = results.get("rq4", {})
    table = rq4.get("language_table", {})
    fisher = rq4.get("cpp_vs_python_fisher", {}) or {}

    lines = [
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{编程语言漏洞特征对比}",
        "\\label{tab:language}",
        "\\begin{tabular}{lrrrr}",
        "\\toprule",
        "语言 & 总数 & 漏洞数 & 密度 & 平均LOC \\\\",
        "\\midrule",
    ]

    if isinstance(table, dict):
        for lang, data in table.items():
            lines.append(
                f"{lang} & {data['total']} & {data['vulnerable']} & "
                f"{data['density']:.3f} & {data.get('avg_loc', 0):.1f} \\\\"
            )
    elif isinstance(table, list):
        for row in table:
            lines.append(
                f"{row['language']} & {row['total']} & {row['vulnerable']} & "
                f"{row['density']:.3f} & {row.get('avg_loc', 0):.1f} \\\\"
            )

    if fisher and isinstance(fisher, dict):
        lines.append("\\midrule")
        or_val = fisher.get("odds_ratio", "-")
        p_val = fisher.get("p_value", "-")
        if isinstance(or_val, (int, float)):
            lines.append(f"\\multicolumn{{5}}{{l}}{{Fisher's exact: OR = {or_val:.2f}, $p$ = {p_val:.4f}}} \\\\")

    lines.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
    ])
    return lines


def _table_api_features(results: Dict) -> List[str]:
    """Table 6: API特征关联"""
    rq5 = results.get("rq5", {})
    tests = rq5.get("feature_fisher_tests", {})

    lines = [
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{ROS API特征与漏洞关联分析}",
        "\\label{tab:api_features}",
        "\\begin{tabular}{lrrrrl}",
        "\\toprule",
        "API特征 & 漏洞中出现 & 良性中出现 & OR & $p_{FDR}$ & 显著 \\\\",
        "\\midrule",
    ]

    for feat, data in sorted(tests.items(), key=lambda x: x[1].get("p_value", 1)):
        vuln_n = data.get("vuln_with_feature", 0)
        benign_n = data.get("benign_with_feature", 0)
        or_val = data.get("odds_ratio", 1)
        p_fdr = data.get("p_adjusted", 1)
        sig = "\\checkmark" if data.get("significant_fdr", False) else ""
        lines.append(
            f"{feat} & {vuln_n} & {benign_n} & {or_val:.2f} & {p_fdr:.4f} & {sig} \\\\"
        )

    lines.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
    ])
    return lines


def _table_antipatterns(results: Dict) -> List[str]:
    """Table 7: 代码反模式"""
    rq6 = results.get("rq6", {})
    patterns = rq6.get("antipattern_prevalence", {})

    lines = [
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{ROS代码反模式检测结果}",
        "\\label{tab:antipatterns}",
        "\\begin{tabular}{lrrrl}",
        "\\toprule",
        "反模式 & 漏洞样本 & 良性样本 & OR & ROS架构根因 \\\\",
        "\\midrule",
    ]

    for pattern, data in patterns.items():
        vuln_n = data.get("vuln_count", 0)
        benign_n = data.get("benign_count", 0)
        or_val = data.get("odds_ratio", 1)
        cause = data.get("ros_cause", "-")[:20]
        lines.append(
            f"{pattern} & {vuln_n} & {benign_n} & {or_val:.2f} & {cause}... \\\\"
        )

    lines.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
    ])
    return lines


def _table_model_comparison(results: Dict) -> List[str]:
    """Table 8: 预测模型对比"""
    rq10 = results.get("rq10", {})
    nested = rq10.get("nested_model_comparison", {})

    lines = [
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{漏洞预测模型对比}",
        "\\label{tab:model_comparison}",
        "\\begin{tabular}{lrrr}",
        "\\toprule",
        "模型 & 特征数 & AUC (5折CV) & 似然比检验 \\\\",
        "\\midrule",
    ]

    for model_key, label in [("complexity_only", "仅复杂度"),
                              ("complexity_plus_api", "复杂度+API"),
                              ("full_model", "全模型")]:
        data = nested.get(model_key, {})
        n_feat = data.get("n_features", "-")
        auc_mean = data.get("auc_mean", 0)
        auc_std = data.get("auc_std", 0)
        lines.append(f"{label} & {n_feat} & {auc_mean:.3f} $\\pm$ {auc_std:.3f} & - \\\\")

    rf_auc = rq10.get("random_forest_auc", {})
    if rf_auc:
        lines.append(
            f"随机森林 & {rq10.get('n_features', '-')} & "
            f"{rf_auc.get('mean', 0):.3f} $\\pm$ {rf_auc.get('std', 0):.3f} & - \\\\"
        )

    lines.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
    ])
    return lines


def save_latex_tables(results: Dict):
    """保存LaTeX表格到文件"""
    content = generate_all_latex_tables(results)
    output_path = OUTPUT_DIR / "empirical_study_v3_tables.tex"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    return output_path
