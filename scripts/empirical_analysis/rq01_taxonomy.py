# [D-RQ1] 漏洞类型分布分析：CWE频率/Shannon熵/卡方检验，motivate CWE专用prompt设计
"""
RQ1: 漏洞类型分布与分类体系
分析CWE分布、多样性指标、集中度、与Top25的相关性、ROS架构层映射
"""
import numpy as np
from collections import Counter
from scipy import stats as scipy_stats
from typing import Dict, List

from .config import *
from .statistical_utils import *
from .data_loader import split_by_label, compute_code_metrics


def rq1_vulnerability_taxonomy(samples: List[Dict]) -> Dict:
    """
    RQ1完整分析：漏洞类型分布与分类体系

    Returns:
        包含所有分析结果的字典
    """
    vuln, benign = split_by_label(samples)
    total_vuln = len(vuln)

    if total_vuln == 0:
        return {"error": "No vulnerable samples found"}

    # ========================================================================
    # 1. CWE分布表（count, percentage, severity breakdown, Top25 rank）
    # ========================================================================
    cwe_counter = Counter(s["_cwe"] for s in vuln)
    severity_by_cwe = {}
    for s in vuln:
        cwe = s["_cwe"]
        sev = s["_severity"]
        if cwe not in severity_by_cwe:
            severity_by_cwe[cwe] = Counter()
        severity_by_cwe[cwe][sev] += 1

    cwe_distribution = []
    for cwe, count in cwe_counter.most_common():
        top25_info = CWE_TOP_25_2024.get(cwe, None)
        entry = {
            "cwe": cwe,
            "count": count,
            "percentage": count / total_vuln * 100,
            "severity_breakdown": dict(severity_by_cwe.get(cwe, {})),
            "top25_rank": top25_info["rank"] if top25_info else None,
            "top25_name": top25_info["name"] if top25_info else None,
        }
        cwe_distribution.append(entry)

    # ========================================================================
    # 2. Shannon entropy + Gini-Simpson diversity index
    # ========================================================================
    counts = list(cwe_counter.values())
    entropy = shannon_entropy(counts)
    max_entropy = np.log2(len(counts)) if len(counts) > 1 else 1.0
    normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0
    diversity_gini_simpson = gini_simpson(counts)

    # ========================================================================
    # 3. Bootstrap 95% CI for each CWE proportion
    # ========================================================================
    cwe_proportion_ci = {}
    for cwe, count in cwe_counter.items():
        prop, ci_lower, ci_upper = bootstrap_proportion_ci(
            count, total_vuln, n_bootstrap=BOOTSTRAP_N, ci=BOOTSTRAP_CI
        )
        cwe_proportion_ci[cwe] = {
            "proportion": prop,
            "ci_lower": ci_lower,
            "ci_upper": ci_upper,
        }

    # ========================================================================
    # 4. Chi-square goodness-of-fit test (observed vs uniform)
    # ========================================================================
    observed = np.array(counts)
    n_categories = len(counts)
    expected_uniform = np.full(n_categories, total_vuln / n_categories)
    chi2_stat, chi2_p = scipy_stats.chisquare(observed, f_exp=expected_uniform)

    chi_square_gof = {
        "chi2_statistic": float(chi2_stat),
        "p_value": float(chi2_p),
        "df": n_categories - 1,
        "significant": chi2_p < ALPHA,
        "interpretation": (
            "Distribution significantly differs from uniform"
            if chi2_p < ALPHA
            else "Distribution does not significantly differ from uniform"
        ),
    }

    # ========================================================================
    # 5. Lorenz curve data + Gini coefficient for concentration
    # ========================================================================
    sorted_counts = np.sort(counts)
    cumulative = np.cumsum(sorted_counts)
    lorenz_y = np.concatenate([[0], cumulative / cumulative[-1]])
    lorenz_x = np.linspace(0, 1, len(lorenz_y))

    gini = gini_coefficient([float(c) for c in counts])

    lorenz_curve = {
        "x": lorenz_x.tolist(),
        "y": lorenz_y.tolist(),
        "gini_coefficient": gini,
        "interpretation": (
            "High concentration" if gini > 0.5
            else "Moderate concentration" if gini > 0.3
            else "Low concentration"
        ),
    }

    # ========================================================================
    # 6. Spearman rank correlation with CWE Top 25
    # ========================================================================
    # Find CWEs that appear in both our dataset and Top 25
    common_cwes = [cwe for cwe in cwe_counter if cwe in CWE_TOP_25_2024]

    spearman_correlation = {}
    if len(common_cwes) >= 3:
        # Our ranking (by count, descending → rank 1 = most frequent)
        our_ranking = sorted(common_cwes, key=lambda c: cwe_counter[c], reverse=True)
        our_ranks = {cwe: rank + 1 for rank, cwe in enumerate(our_ranking)}

        # Top 25 ranks
        top25_ranks = {cwe: CWE_TOP_25_2024[cwe]["rank"] for cwe in common_cwes}

        our_rank_values = [our_ranks[cwe] for cwe in common_cwes]
        top25_rank_values = [top25_ranks[cwe] for cwe in common_cwes]

        rho, sp_p = scipy_stats.spearmanr(our_rank_values, top25_rank_values)
        spearman_correlation = {
            "rho": float(rho),
            "p_value": float(sp_p),
            "significant": sp_p < ALPHA,
            "n_common_cwes": len(common_cwes),
            "common_cwes": common_cwes,
            "our_ranks": our_ranks,
            "top25_ranks": top25_ranks,
            "interpretation": (
                "Significant positive correlation with CWE Top 25"
                if sp_p < ALPHA and rho > 0
                else "Significant negative correlation with CWE Top 25"
                if sp_p < ALPHA and rho < 0
                else "No significant correlation with CWE Top 25"
            ),
        }
    else:
        spearman_correlation = {
            "rho": None,
            "p_value": None,
            "significant": None,
            "n_common_cwes": len(common_cwes),
            "note": "Insufficient common CWEs for correlation (need >= 3)",
        }

    # ========================================================================
    # 7. ROS architecture layer mapping
    # ========================================================================
    layer_counts = Counter()
    unmapped_cwes = []
    for s in vuln:
        cwe = s["_cwe"]
        layer = CWE_TO_ROS_LAYER.get(cwe, None)
        if layer:
            layer_counts[layer] += 1
        else:
            unmapped_cwes.append(cwe)

    unmapped_counter = Counter(unmapped_cwes)
    total_mapped = sum(layer_counts.values())

    ros_layer_mapping = {
        "layer_distribution": {
            layer: {
                "count": count,
                "percentage": count / total_vuln * 100,
                "percentage_of_mapped": count / total_mapped * 100 if total_mapped > 0 else 0,
            }
            for layer, count in layer_counts.most_common()
        },
        "total_mapped": total_mapped,
        "total_unmapped": len(unmapped_cwes),
        "mapped_percentage": total_mapped / total_vuln * 100,
        "unmapped_cwes": dict(unmapped_counter.most_common()),
    }

    # ========================================================================
    # 8. Findings
    # ========================================================================
    top3_cwes = cwe_counter.most_common(3)
    top3_pct = sum(c for _, c in top3_cwes) / total_vuln * 100

    findings = []
    findings.append(
        f"共识别 {len(cwe_counter)} 种不同CWE类型，"
        f"前3种（{', '.join(c for c, _ in top3_cwes)}）占总漏洞的 {top3_pct:.1f}%"
    )
    findings.append(
        f"Shannon熵 = {entropy:.3f}（归一化 = {normalized_entropy:.3f}），"
        f"Gini-Simpson = {diversity_gini_simpson:.3f}"
    )
    findings.append(
        f"Gini系数 = {gini:.3f}，表明漏洞类型分布{lorenz_curve['interpretation']}"
    )
    if chi_square_gof["significant"]:
        findings.append(
            f"卡方拟合优度检验显著（χ² = {chi2_stat:.2f}, p < 0.001），"
            "漏洞类型分布显著偏离均匀分布"
        )
    if spearman_correlation.get("significant"):
        findings.append(
            f"与CWE Top 25排名存在显著相关性（ρ = {spearman_correlation['rho']:.3f}, "
            f"p = {spearman_correlation['p_value']:.4f}）"
        )
    if ros_layer_mapping["total_mapped"] > 0:
        top_layer = layer_counts.most_common(1)[0]
        findings.append(
            f"ROS架构层映射：{top_layer[0]}是最主要的漏洞来源层"
            f"（{top_layer[1]}个漏洞，占已映射的"
            f"{top_layer[1] / total_mapped * 100:.1f}%）"
        )

    # ========================================================================
    # 汇总返回
    # ========================================================================
    return {
        "n_vulnerable": total_vuln,
        "n_benign": len(benign),
        "n_cwe_types": len(cwe_counter),
        "cwe_distribution": cwe_distribution,
        "diversity": {
            "shannon_entropy": entropy,
            "max_entropy": float(max_entropy),
            "normalized_entropy": normalized_entropy,
            "gini_simpson": diversity_gini_simpson,
        },
        "cwe_proportion_ci": cwe_proportion_ci,
        "chi_square_goodness_of_fit": chi_square_gof,
        "lorenz_curve": lorenz_curve,
        "spearman_correlation_top25": spearman_correlation,
        "ros_layer_mapping": ros_layer_mapping,
        "findings": findings,
    }
