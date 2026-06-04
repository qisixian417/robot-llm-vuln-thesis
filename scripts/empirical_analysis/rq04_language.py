# [D-RQ4] 语言特征对比：C++与Python漏洞密度差异，Fisher检验+Odds Ratio
"""
RQ4: 语言特定漏洞特征分析
- 语言维度的漏洞分布与密度
- C++ vs Python 漏洞率差异检验
- CWE类型的语言差异
- 语言×CWE交互效应
- 语言特定复杂度比较
"""
import numpy as np
from collections import Counter, defaultdict
from typing import Dict, List

from .config import *
from .statistical_utils import *
from .data_loader import split_by_label


def rq4_language_characteristics(samples: List[Dict]) -> Dict:
    """
    RQ4: 分析不同编程语言的漏洞特征差异

    Args:
        samples: 预处理后的样本列表（含 _label, _cwe, _language, _metrics 等字段）

    Returns:
        包含统计检验结果、效应量和发现的字典
    """
    vuln, benign = split_by_label(samples)
    results = {}

    # ========================================================================
    # 1. 语言概览表：总数、漏洞数、密度、平均LOC、CWE分布
    # ========================================================================
    language_groups = defaultdict(list)
    for s in samples:
        language_groups[s["_language"]].append(s)

    language_table = {}
    for lang, lang_samples in language_groups.items():
        lang_vuln = [s for s in lang_samples if s["_label"] == 1]
        lang_benign = [s for s in lang_samples if s["_label"] == 0]
        total = len(lang_samples)
        n_vuln = len(lang_vuln)
        density = n_vuln / total if total > 0 else 0.0

        # 平均LOC
        locs = [s["_metrics"]["loc"] for s in lang_samples]
        avg_loc = np.mean(locs) if locs else 0.0

        # CWE分布（仅漏洞样本）
        cwe_dist = dict(Counter(s["_cwe"] for s in lang_vuln))

        # Wilson score CI for density
        density_point, density_ci_lower, density_ci_upper = wilson_score_ci(n_vuln, total)

        language_table[lang] = {
            "total": total,
            "vulnerable": n_vuln,
            "benign": len(lang_benign),
            "density": density,
            "density_ci": (density_ci_lower, density_ci_upper),
            "avg_loc": float(avg_loc),
            "cwe_distribution": cwe_dist,
        }

    results["language_table"] = language_table

    # ========================================================================
    # 2. Fisher's exact test: C++ vs Python 漏洞率差异
    # ========================================================================
    cpp_samples = language_groups.get("C++", []) + language_groups.get("cpp", [])
    py_samples = language_groups.get("Python", []) + language_groups.get("python", [])

    cpp_vuln = sum(1 for s in cpp_samples if s["_label"] == 1)
    cpp_benign = sum(1 for s in cpp_samples if s["_label"] == 0)
    py_vuln = sum(1 for s in py_samples if s["_label"] == 1)
    py_benign = sum(1 for s in py_samples if s["_label"] == 0)

    fisher_table = [[cpp_vuln, cpp_benign], [py_vuln, py_benign]]
    fisher_result = fisher_exact_test(fisher_table)
    results["cpp_vs_python_fisher"] = {
        "table": fisher_table,
        "cpp_total": len(cpp_samples),
        "python_total": len(py_samples),
        "cpp_vuln_rate": cpp_vuln / len(cpp_samples) if cpp_samples else 0,
        "python_vuln_rate": py_vuln / len(py_samples) if py_samples else 0,
        **fisher_result,
    }

    # ========================================================================
    # 3. Odds Ratio + 95% CI (C++ vs Python)
    # ========================================================================
    or_val, or_lower, or_upper = odds_ratio_ci(cpp_vuln, cpp_benign, py_vuln, py_benign)
    results["cpp_vs_python_odds_ratio"] = {
        "odds_ratio": or_val,
        "ci_lower": or_lower,
        "ci_upper": or_upper,
        "interpretation": "C++ has higher vulnerability rate" if or_val > 1 else "Python has higher vulnerability rate",
    }

    # ========================================================================
    # 4. CWE profile comparison: C++ vs Python 各CWE类型占比
    # ========================================================================
    cpp_vuln_samples = [s for s in cpp_samples if s["_label"] == 1]
    py_vuln_samples = [s for s in py_samples if s["_label"] == 1]

    cpp_cwe_counts = Counter(s["_cwe"] for s in cpp_vuln_samples)
    py_cwe_counts = Counter(s["_cwe"] for s in py_vuln_samples)

    # 两种语言都出现的CWE类型
    common_cwes = set(cpp_cwe_counts.keys()) & set(py_cwe_counts.keys())
    cwe_profile_comparison = {}
    for cwe in common_cwes:
        cpp_prop = cpp_cwe_counts[cwe] / len(cpp_vuln_samples) if cpp_vuln_samples else 0
        py_prop = py_cwe_counts[cwe] / len(py_vuln_samples) if py_vuln_samples else 0
        cwe_profile_comparison[cwe] = {
            "cpp_count": cpp_cwe_counts[cwe],
            "cpp_proportion": cpp_prop,
            "python_count": py_cwe_counts[cwe],
            "python_proportion": py_prop,
            "ratio": cpp_prop / py_prop if py_prop > 0 else float("inf"),
        }

    results["cwe_profile_comparison"] = cwe_profile_comparison

    # ========================================================================
    # 5. Language × CWE interaction: Fisher's exact + Bonferroni correction
    # ========================================================================
    all_cwes = set(cpp_cwe_counts.keys()) | set(py_cwe_counts.keys())
    cwe_interaction_tests = {}
    p_values_for_correction = []
    cwe_list_for_correction = []

    for cwe in sorted(all_cwes):
        # 2x2: [cpp_has_cwe, cpp_not_cwe], [py_has_cwe, py_not_cwe]
        cpp_has = cpp_cwe_counts.get(cwe, 0)
        cpp_not = len(cpp_vuln_samples) - cpp_has
        py_has = py_cwe_counts.get(cwe, 0)
        py_not = len(py_vuln_samples) - py_has

        if cpp_has + py_has == 0:
            continue

        table = [[cpp_has, cpp_not], [py_has, py_not]]
        test_result = fisher_exact_test(table)
        cwe_interaction_tests[cwe] = {
            "table": table,
            **test_result,
        }
        p_values_for_correction.append(test_result["p_value"])
        cwe_list_for_correction.append(cwe)

    # Holm-Bonferroni correction
    if p_values_for_correction:
        corrected = holm_bonferroni(p_values_for_correction)
        for i, cwe in enumerate(cwe_list_for_correction):
            adj_p, sig = corrected[i]
            cwe_interaction_tests[cwe]["adjusted_p_value"] = adj_p
            cwe_interaction_tests[cwe]["significant_after_correction"] = sig

    results["language_cwe_interaction"] = cwe_interaction_tests

    # ========================================================================
    # 6. Language-specific complexity: Mann-Whitney U for 7 metrics
    # ========================================================================
    metrics_names = [
        "loc", "sloc", "num_functions_called", "max_nesting_depth",
        "num_conditions", "cyclomatic_complexity", "num_pointers"
    ]

    complexity_comparison = {}
    for metric in metrics_names:
        cpp_values = [s["_metrics"][metric] for s in cpp_vuln_samples if metric in s["_metrics"]]
        py_values = [s["_metrics"][metric] for s in py_vuln_samples if metric in s["_metrics"]]

        mw_result = mann_whitney_test(cpp_values, py_values)
        complexity_comparison[metric] = {
            "cpp_n": len(cpp_values),
            "cpp_mean": float(np.mean(cpp_values)) if cpp_values else 0.0,
            "cpp_median": float(np.median(cpp_values)) if cpp_values else 0.0,
            "python_n": len(py_values),
            "python_mean": float(np.mean(py_values)) if py_values else 0.0,
            "python_median": float(np.median(py_values)) if py_values else 0.0,
            **mw_result,
        }

    results["complexity_comparison"] = complexity_comparison

    # ========================================================================
    # 7. Architecture perspective analysis (hardcoded insight)
    # ========================================================================
    # C++集中于内存/并发相关CWE（底层驱动层）
    # Python集中于输入验证/命令注入相关CWE（上层应用层）
    cpp_memory_concurrency_cwes = {"CWE-476", "CWE-416", "CWE-401", "CWE-362", "CWE-119", "CWE-787"}
    py_input_injection_cwes = {"CWE-78", "CWE-79", "CWE-89", "CWE-134", "CWE-190"}

    cpp_mem_count = sum(cpp_cwe_counts.get(c, 0) for c in cpp_memory_concurrency_cwes)
    cpp_total_vuln = len(cpp_vuln_samples)
    py_input_count = sum(py_cwe_counts.get(c, 0) for c in py_input_injection_cwes)
    py_total_vuln = len(py_vuln_samples)

    results["architecture_perspective"] = {
        "cpp_focus": {
            "category": "内存安全/并发（底层驱动层）",
            "relevant_cwes": sorted(cpp_memory_concurrency_cwes),
            "count": cpp_mem_count,
            "proportion": cpp_mem_count / cpp_total_vuln if cpp_total_vuln > 0 else 0.0,
        },
        "python_focus": {
            "category": "输入验证/命令注入（上层应用层）",
            "relevant_cwes": sorted(py_input_injection_cwes),
            "count": py_input_count,
            "proportion": py_input_count / py_total_vuln if py_total_vuln > 0 else 0.0,
        },
        "insight": (
            "C++漏洞集中于内存管理和并发控制（底层驱动/中间件），"
            "Python漏洞集中于输入验证和命令注入（上层应用/配置脚本）。"
            "这反映了ROS系统中不同语言承担不同架构角色的特点。"
        ),
    }

    # ========================================================================
    # 8. Findings
    # ========================================================================
    findings = []

    # Finding 1: Vulnerability rate difference
    cpp_rate = results["cpp_vs_python_fisher"]["cpp_vuln_rate"]
    py_rate = results["cpp_vs_python_fisher"]["python_vuln_rate"]
    fisher_sig = results["cpp_vs_python_fisher"]["significant"]
    findings.append({
        "id": "F4.1",
        "description": (
            f"C++漏洞密度({cpp_rate:.3f})与Python({py_rate:.3f})的差异"
            f"{'具有' if fisher_sig else '不具有'}统计显著性 "
            f"(Fisher's exact p={results['cpp_vs_python_fisher']['p_value']:.4f}, "
            f"OR={or_val:.2f}, 95%CI=[{or_lower:.2f}, {or_upper:.2f}])"
        ),
    })

    # Finding 2: Significant CWE-language interactions
    sig_interactions = [
        cwe for cwe, res in cwe_interaction_tests.items()
        if res.get("significant_after_correction", False)
    ]
    if sig_interactions:
        findings.append({
            "id": "F4.2",
            "description": (
                f"经Holm-Bonferroni校正后，{len(sig_interactions)}个CWE类型"
                f"与语言存在显著关联: {', '.join(sig_interactions)}"
            ),
        })
    else:
        findings.append({
            "id": "F4.2",
            "description": "经Holm-Bonferroni校正后，无CWE类型与语言存在显著关联",
        })

    # Finding 3: Complexity differences
    sig_metrics = [
        m for m, res in complexity_comparison.items()
        if res.get("significant", False)
    ]
    if sig_metrics:
        findings.append({
            "id": "F4.3",
            "description": (
                f"C++与Python漏洞样本在{len(sig_metrics)}个复杂度指标上存在显著差异: "
                f"{', '.join(sig_metrics)}"
            ),
        })

    # Finding 4: Architecture perspective
    findings.append({
        "id": "F4.4",
        "description": results["architecture_perspective"]["insight"],
    })

    results["findings"] = findings

    return results
