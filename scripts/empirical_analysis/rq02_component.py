# [D-RQ2] ROS组件漏洞密度分析：7类组件对比，Fisher检验+Cramér's V效应量
"""
RQ2: ROS组件与架构根因分析
分析组件漏洞密度、Odds Ratio、Fisher精确检验、ROS版本比较、组件×CWE独立性
"""
import numpy as np
from collections import Counter
from scipy import stats as scipy_stats
from typing import Dict, List

from .config import *
from .statistical_utils import *
from .data_loader import split_by_label, compute_code_metrics


def rq2_component_architecture(samples: List[Dict]) -> Dict:
    """
    RQ2完整分析：ROS组件与架构根因分析

    Returns:
        包含所有分析结果的字典
    """
    vuln, benign = split_by_label(samples)
    total_samples = len(samples)
    total_vuln = len(vuln)
    total_benign = len(benign)

    if total_samples == 0:
        return {"error": "No samples found"}

    # ========================================================================
    # 1. Component vulnerability density table
    # ========================================================================
    component_counter = Counter(s["_component"] for s in samples)
    component_vuln_counter = Counter(s["_component"] for s in vuln)

    # Top CWE per component
    component_cwe = {}
    for s in vuln:
        comp = s["_component"]
        if comp not in component_cwe:
            component_cwe[comp] = Counter()
        component_cwe[comp][s["_cwe"]] += 1

    component_density_table = []
    for comp, total_count in component_counter.most_common():
        vuln_count = component_vuln_counter.get(comp, 0)
        density = vuln_count / total_count if total_count > 0 else 0.0
        top_cwe = (
            component_cwe[comp].most_common(1)[0] if comp in component_cwe else (None, 0)
        )
        component_density_table.append({
            "component": comp,
            "total": total_count,
            "vulnerable": vuln_count,
            "benign": total_count - vuln_count,
            "density": density,
            "top_cwe": top_cwe[0],
            "top_cwe_count": top_cwe[1],
        })

    # ========================================================================
    # 2. Odds Ratio + 95% CI for each component
    # ========================================================================
    component_odds_ratios = {}
    for comp in component_counter:
        # 2x2 table: [[in_comp & vuln, in_comp & benign], [not_comp & vuln, not_comp & benign]]
        in_comp_vuln = sum(1 for s in vuln if s["_component"] == comp)
        in_comp_benign = sum(1 for s in benign if s["_component"] == comp)
        not_comp_vuln = total_vuln - in_comp_vuln
        not_comp_benign = total_benign - in_comp_benign

        or_val, or_lower, or_upper = odds_ratio_ci(
            in_comp_vuln, in_comp_benign, not_comp_vuln, not_comp_benign
        )
        component_odds_ratios[comp] = {
            "odds_ratio": or_val,
            "ci_lower": or_lower,
            "ci_upper": or_upper,
            "significant": or_lower > 1.0 or or_upper < 1.0,
            "interpretation": (
                "Risk factor" if or_lower > 1.0
                else "Protective factor" if or_upper < 1.0
                else "Not significant"
            ),
        }

    # ========================================================================
    # 3. Fisher's exact test for each component
    # ========================================================================
    component_fisher = {}
    for comp in component_counter:
        in_comp_vuln = sum(1 for s in vuln if s["_component"] == comp)
        in_comp_benign = sum(1 for s in benign if s["_component"] == comp)
        not_comp_vuln = total_vuln - in_comp_vuln
        not_comp_benign = total_benign - in_comp_benign

        table_2x2 = [[in_comp_vuln, in_comp_benign],
                      [not_comp_vuln, not_comp_benign]]
        result = fisher_exact_test(table_2x2)
        component_fisher[comp] = result

    # Apply Holm-Bonferroni correction to Fisher p-values
    fisher_p_values = [component_fisher[comp]["p_value"] for comp in component_counter]
    corrected = holm_bonferroni(fisher_p_values)
    for i, comp in enumerate(component_counter):
        component_fisher[comp]["p_adjusted"] = corrected[i][0]
        component_fisher[comp]["significant_adjusted"] = corrected[i][1]

    # ========================================================================
    # 4. ROS1 vs ROS2 comparison
    # ========================================================================
    ros1_samples = [s for s in samples if "1" in s.get("_ros_version", "")]
    ros2_samples = [s for s in samples if "2" in s.get("_ros_version", "")]

    ros1_vuln = sum(1 for s in ros1_samples if s["_label"] == 1)
    ros2_vuln = sum(1 for s in ros2_samples if s["_label"] == 1)
    ros1_total = len(ros1_samples)
    ros2_total = len(ros2_samples)

    ros_version_comparison = {
        "ros1": {
            "total": ros1_total,
            "vulnerable": ros1_vuln,
            "density": ros1_vuln / ros1_total if ros1_total > 0 else 0.0,
        },
        "ros2": {
            "total": ros2_total,
            "vulnerable": ros2_vuln,
            "density": ros2_vuln / ros2_total if ros2_total > 0 else 0.0,
        },
    }

    if ros1_total > 0 and ros2_total > 0:
        z_test_result = proportion_z_test(ros1_vuln, ros1_total, ros2_vuln, ros2_total)
        ros_version_comparison["z_test"] = z_test_result
    else:
        ros_version_comparison["z_test"] = {
            "note": "Insufficient data for one or both ROS versions"
        }

    # ========================================================================
    # 5. Chi-square independence test (component × CWE)
    # ========================================================================
    # Collapse sparse components (< 10 samples) into "other_minor"
    MIN_COMPONENT_SIZE = 10
    component_map = {}
    for comp, count in component_counter.items():
        if count >= MIN_COMPONENT_SIZE:
            component_map[comp] = comp
        else:
            component_map[comp] = "other_minor"

    # Build contingency table only from vulnerable samples
    vuln_mapped_comp = [component_map[s["_component"]] for s in vuln]
    vuln_cwes = [s["_cwe"] for s in vuln]

    comp_labels = sorted(set(vuln_mapped_comp))
    cwe_labels = sorted(set(vuln_cwes))

    if len(comp_labels) >= 2 and len(cwe_labels) >= 2:
        contingency = np.zeros((len(comp_labels), len(cwe_labels)), dtype=int)
        comp_idx = {c: i for i, c in enumerate(comp_labels)}
        cwe_idx = {c: i for i, c in enumerate(cwe_labels)}

        for comp, cwe in zip(vuln_mapped_comp, vuln_cwes):
            contingency[comp_idx[comp], cwe_idx[cwe]] += 1

        # Remove columns/rows that are all zeros
        row_mask = contingency.sum(axis=1) > 0
        col_mask = contingency.sum(axis=0) > 0
        contingency_clean = contingency[row_mask][:, col_mask]
        comp_labels_clean = [c for c, m in zip(comp_labels, row_mask) if m]
        cwe_labels_clean = [c for c, m in zip(cwe_labels, col_mask) if m]

        if contingency_clean.shape[0] >= 2 and contingency_clean.shape[1] >= 2:
            chi2_stat, chi2_p, chi2_dof, expected = scipy_stats.chi2_contingency(
                contingency_clean
            )
            cv = cramers_v(contingency_clean)
            cv_interpretation = interpret_cramers_v(cv)

            chi_square_independence = {
                "chi2_statistic": float(chi2_stat),
                "p_value": float(chi2_p),
                "df": int(chi2_dof),
                "significant": chi2_p < ALPHA,
                "contingency_shape": list(contingency_clean.shape),
                "component_labels": comp_labels_clean,
                "cwe_labels": cwe_labels_clean,
                "min_component_size_threshold": MIN_COMPONENT_SIZE,
            }
        else:
            chi_square_independence = {
                "note": "Insufficient categories after collapsing sparse cells"
            }
            cv = 0.0
            cv_interpretation = "negligible"
    else:
        chi_square_independence = {
            "note": "Insufficient categories for chi-square test"
        }
        cv = 0.0
        cv_interpretation = "negligible"

    # ========================================================================
    # 6. Cramér's V with interpretation
    # ========================================================================
    cramers_v_result = {
        "value": cv,
        "interpretation": cv_interpretation,
    }

    # ========================================================================
    # 7. Root cause attribution (domain knowledge)
    # ========================================================================
    # Sort components by vulnerability count
    top_components = sorted(
        component_vuln_counter.items(), key=lambda x: x[1], reverse=True
    )[:3]

    root_cause_knowledge = {
        "rcl": (
            "ROS Client Library (rcl) 是所有ROS节点的核心运行时库，负责节点生命周期管理、"
            "内存分配与释放。其C语言实现缺乏自动内存管理，导致大量CWE-476（空指针解引用）"
            "和CWE-401（内存泄漏）。回调机制中的异步资源释放是UAF漏洞的主要来源。"
        ),
        "rclcpp": (
            "rclcpp是ROS2的C++客户端库，虽然使用了智能指针，但在Executor回调调度中"
            "仍存在生命周期管理问题。多线程Executor的并发回调可能导致CWE-362（竞态条件），"
            "shared_ptr循环引用导致CWE-401（内存泄漏）。"
        ),
        "nav2": (
            "Navigation2是ROS2的导航框架，涉及大量实时路径规划和传感器数据处理。"
            "高频率的costmap更新和TF变换查询中存在CWE-119（缓冲区溢出）风险，"
            "多线程行为树执行器中存在CWE-362（竞态条件）。"
        ),
        "moveit": (
            "MoveIt是机械臂运动规划框架，涉及复杂的碰撞检测和轨迹优化计算。"
            "大量矩阵运算中存在CWE-190（整数溢出）风险，"
            "插件式架构的动态加载可能导致CWE-416（UAF）。"
        ),
        "ros_comm": (
            "ros_comm是ROS1的核心通信库，负责话题、服务、参数服务器的底层实现。"
            "其XML-RPC接口缺乏输入验证，存在CWE-78（命令注入）风险。"
            "序列化/反序列化过程中的长度字段未校验导致CWE-119（缓冲区溢出）。"
        ),
        "gazebo": (
            "Gazebo仿真器处理大量物理引擎计算和3D渲染，涉及复杂的内存管理。"
            "插件系统的动态加载/卸载容易产生CWE-416（UAF），"
            "SDF模型解析中存在CWE-119（缓冲区溢出）。"
        ),
    }

    # Default explanation for unknown components
    default_explanation = (
        "该组件的漏洞集中模式可能与其特定的功能域和编程模式相关，"
        "需要进一步的代码审计来确定具体根因。"
    )

    root_cause_attribution = []
    for comp, count in top_components:
        top_cwes_for_comp = (
            component_cwe[comp].most_common(3) if comp in component_cwe else []
        )
        root_cause_attribution.append({
            "component": comp,
            "vuln_count": count,
            "top_cwes": [{"cwe": c, "count": n} for c, n in top_cwes_for_comp],
            "root_cause_explanation": root_cause_knowledge.get(comp, default_explanation),
        })

    # ========================================================================
    # 8. Findings
    # ========================================================================
    findings = []

    # Top component finding
    if component_density_table:
        top_comp = max(component_density_table, key=lambda x: x["density"])
        findings.append(
            f"漏洞密度最高的组件是 {top_comp['component']}（密度={top_comp['density']:.3f}，"
            f"{top_comp['vulnerable']}/{top_comp['total']}）"
        )

    # Significant OR findings
    sig_risk_factors = [
        comp for comp, result in component_odds_ratios.items()
        if result["interpretation"] == "Risk factor"
    ]
    if sig_risk_factors:
        findings.append(
            f"以下组件是显著的漏洞风险因子（OR CI下界 > 1）：{', '.join(sig_risk_factors)}"
        )

    # ROS version comparison
    if ros_version_comparison.get("z_test", {}).get("significant"):
        z_result = ros_version_comparison["z_test"]
        findings.append(
            f"ROS1与ROS2漏洞密度存在显著差异（z = {z_result['z_statistic']:.3f}, "
            f"p = {z_result['p_value']:.4f}），"
            f"ROS1密度={ros_version_comparison['ros1']['density']:.3f}，"
            f"ROS2密度={ros_version_comparison['ros2']['density']:.3f}"
        )
    elif ros1_total > 0 and ros2_total > 0:
        findings.append(
            f"ROS1与ROS2漏洞密度无显著差异"
            f"（ROS1={ros_version_comparison['ros1']['density']:.3f}，"
            f"ROS2={ros_version_comparison['ros2']['density']:.3f}）"
        )

    # Chi-square finding
    if chi_square_independence.get("significant"):
        findings.append(
            f"组件与CWE类型之间存在显著关联（χ² = {chi_square_independence['chi2_statistic']:.2f}, "
            f"p = {chi_square_independence['p_value']:.4e}），"
            f"Cramér's V = {cv:.3f}（{cv_interpretation}效应）"
        )

    # ========================================================================
    # 汇总返回
    # ========================================================================
    return {
        "n_samples": total_samples,
        "n_vulnerable": total_vuln,
        "n_benign": total_benign,
        "n_components": len(component_counter),
        "component_density_table": component_density_table,
        "component_odds_ratios": component_odds_ratios,
        "component_fisher_tests": component_fisher,
        "ros_version_comparison": ros_version_comparison,
        "chi_square_independence": chi_square_independence,
        "cramers_v": cramers_v_result,
        "root_cause_attribution": root_cause_attribution,
        "findings": findings,
    }
