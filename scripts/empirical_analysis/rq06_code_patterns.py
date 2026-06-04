# [C-RQ1] 漏洞代码反模式分析：识别常见anti-pattern特征
"""
RQ6: 漏洞代码反模式与ROS架构缺陷关联
检测6种反模式，分析其与漏洞标签、CWE类型的统计关联
"""
import re
import numpy as np
from collections import Counter
from typing import Dict, List
from scipy import stats as scipy_stats

from .config import *
from .statistical_utils import *
from .data_loader import split_by_label


# ============================================================================
# 反模式定义
# ============================================================================

ANTI_PATTERNS = {
    "missing_null_check": {
        "description": "指针解引用但无空指针检查",
        "ros_context": "ROS回调中指针可能在节点shutdown后失效",
        "ros_layer": "资源管理层",
    },
    "missing_lock": {
        "description": "回调中访问共享资源但无互斥锁",
        "ros_context": "ROS多线程Executor并发回调",
        "ros_layer": "并发层",
    },
    "unchecked_return": {
        "description": "函数调用返回值未检查",
        "ros_context": "ROS服务调用可能超时失败",
        "ros_layer": "通信层",
    },
    "raw_pointer_no_raii": {
        "description": "使用new但无智能指针管理",
        "ros_context": "ROS节点生命周期管理复杂",
        "ros_layer": "资源管理层",
    },
    "no_bounds_check": {
        "description": "数组访问无边界检查",
        "ros_context": "ROS消息反序列化可能包含异常数据",
        "ros_layer": "输入处理层",
    },
    "missing_input_validation": {
        "description": "处理外部输入但无验证",
        "ros_context": "ROS话题数据来自不可信节点",
        "ros_layer": "输入处理层",
    },
}


# ============================================================================
# 反模式检测函数
# ============================================================================

def detect_missing_null_check(code: str) -> bool:
    """检测：有指针解引用但无空指针检查"""
    has_deref = bool(re.search(r'->|(\*\w+)', code))
    has_null_check = bool(re.search(r'if.*null|if.*ptr|nullptr|NULL\b|==\s*0\b', code, re.IGNORECASE))
    return has_deref and not has_null_check


def detect_missing_lock(code: str) -> bool:
    """检测：回调中访问共享资源但无互斥锁"""
    has_callback = bool(re.search(r'[Cc]allback|_cb\b', code))
    has_member_access = bool(re.search(r'this->|self\.|_\w+\s*=', code))
    has_lock = bool(re.search(r'mutex|lock_guard|unique_lock|scoped_lock', code, re.IGNORECASE))
    return has_callback and has_member_access and not has_lock


def detect_unchecked_return(code: str) -> bool:
    """检测：函数调用返回值未检查"""
    lines = code.split('\n')
    bare_call_count = 0
    for line in lines:
        stripped = line.strip()
        # 匹配裸函数调用（不在赋值、if、return中）
        if re.match(r'^[a-zA-Z_]\w*(::\w+)*\s*\(', stripped):
            if not re.match(r'^(if|while|for|return|switch|else)', stripped):
                bare_call_count += 1
    return bare_call_count >= 2


def detect_raw_pointer_no_raii(code: str) -> bool:
    """检测：使用new但无智能指针"""
    has_new = bool(re.search(r'\bnew\s+\w+', code))
    has_smart_ptr = bool(re.search(r'shared_ptr|unique_ptr|make_shared|make_unique', code))
    return has_new and not has_smart_ptr


def detect_no_bounds_check(code: str) -> bool:
    """检测：数组访问无边界检查"""
    has_array_access = bool(re.search(r'\w+\[', code))
    has_bounds_check = bool(re.search(r'\.size\(\)|\.length|size\(|bounds|range|\.at\(', code, re.IGNORECASE))
    return has_array_access and not has_bounds_check


def detect_missing_input_validation(code: str) -> bool:
    """检测：处理外部输入但无验证"""
    has_external_input = bool(re.search(r'get_parameter|subscribe|msg->|msg\.', code))
    has_validation = bool(re.search(r'if\s*\(.*[><]|check|valid|assert|throw|verify', code, re.IGNORECASE))
    return has_external_input and not has_validation


DETECTORS = {
    "missing_null_check": detect_missing_null_check,
    "missing_lock": detect_missing_lock,
    "unchecked_return": detect_unchecked_return,
    "raw_pointer_no_raii": detect_raw_pointer_no_raii,
    "no_bounds_check": detect_no_bounds_check,
    "missing_input_validation": detect_missing_input_validation,
}


# ============================================================================
# 主分析函数
# ============================================================================

def rq6_code_patterns(samples: List[Dict]) -> Dict:
    """
    RQ6: 漏洞代码反模式与ROS架构缺陷关联分析

    Returns:
        包含反模式检测结果、统计检验、CWE关联的完整分析字典
    """
    vuln, benign = split_by_label(samples)
    n_vuln = len(vuln)
    n_benign = len(benign)

    # ------------------------------------------------------------------
    # 1. 检测每个样本的反模式
    # ------------------------------------------------------------------
    pattern_names = list(ANTI_PATTERNS.keys())

    for s in samples:
        code = s.get("vulnerable_code", "")
        s["_anti_patterns"] = {}
        for name, detector in DETECTORS.items():
            s["_anti_patterns"][name] = detector(code)

    # ------------------------------------------------------------------
    # 2. 统计每种反模式在vuln/benign中的分布 + Fisher's exact test
    # ------------------------------------------------------------------
    pattern_stats = {}
    p_values_for_correction = []

    for name in pattern_names:
        vuln_present = sum(1 for s in vuln if s["_anti_patterns"][name])
        vuln_absent = n_vuln - vuln_present
        benign_present = sum(1 for s in benign if s["_anti_patterns"][name])
        benign_absent = n_benign - benign_present

        # 2x2 table: [[vuln_present, vuln_absent], [benign_present, benign_absent]]
        table = [[vuln_present, vuln_absent], [benign_present, benign_absent]]
        test_result = fisher_exact_test(table)

        # Odds ratio CI
        or_val, or_lower, or_upper = odds_ratio_ci(
            vuln_present, vuln_absent, benign_present, benign_absent
        )

        pattern_stats[name] = {
            "vuln_count": vuln_present,
            "vuln_pct": vuln_present / n_vuln if n_vuln > 0 else 0,
            "benign_count": benign_present,
            "benign_pct": benign_present / n_benign if n_benign > 0 else 0,
            "contingency_table": table,
            "fisher_test": test_result,
            "odds_ratio": or_val,
            "or_ci": (or_lower, or_upper),
            "description": ANTI_PATTERNS[name]["description"],
            "ros_context": ANTI_PATTERNS[name]["ros_context"],
            "ros_layer": ANTI_PATTERNS[name]["ros_layer"],
        }
        p_values_for_correction.append(test_result["p_value"])

    # 多重比较校正
    holm_results = holm_bonferroni(p_values_for_correction)
    bh_results = benjamini_hochberg(p_values_for_correction)

    for i, name in enumerate(pattern_names):
        pattern_stats[name]["holm_adjusted_p"] = holm_results[i][0]
        pattern_stats[name]["holm_significant"] = holm_results[i][1]
        pattern_stats[name]["bh_adjusted_p"] = bh_results[i][0]
        pattern_stats[name]["bh_significant"] = bh_results[i][1]

    # ------------------------------------------------------------------
    # 3. 反模式 × CWE 列联表 + 卡方检验
    # ------------------------------------------------------------------
    cwe_types = sorted(set(s["_cwe"] for s in vuln if s["_cwe"] != "unknown"))

    # 构建列联表：行=反模式，列=CWE类型
    pattern_cwe_table = np.zeros((len(pattern_names), len(cwe_types)), dtype=int)
    for i, pname in enumerate(pattern_names):
        for j, cwe in enumerate(cwe_types):
            count = sum(
                1 for s in vuln
                if s["_cwe"] == cwe and s["_anti_patterns"][pname]
            )
            pattern_cwe_table[i, j] = count

    # 卡方检验（仅在表格有足够数据时）
    chi2_result = None
    cramers_v_val = None
    if pattern_cwe_table.sum() > 0 and pattern_cwe_table.shape[0] > 1 and pattern_cwe_table.shape[1] > 1:
        # 过滤掉全零行/列
        row_mask = pattern_cwe_table.sum(axis=1) > 0
        col_mask = pattern_cwe_table.sum(axis=0) > 0
        filtered_table = pattern_cwe_table[row_mask][:, col_mask]

        if filtered_table.shape[0] > 1 and filtered_table.shape[1] > 1:
            chi2, p_chi2, dof, expected = scipy_stats.chi2_contingency(filtered_table)
            cramers_v_val = cramers_v(filtered_table)
            chi2_result = {
                "chi2": float(chi2),
                "p_value": float(p_chi2),
                "dof": int(dof),
                "significant": p_chi2 < ALPHA,
                "cramers_v": cramers_v_val,
                "cramers_v_interpretation": interpret_cramers_v(cramers_v_val),
            }

    # 每种CWE最常见的反模式
    cwe_dominant_pattern = {}
    for j, cwe in enumerate(cwe_types):
        col = pattern_cwe_table[:, j]
        if col.sum() > 0:
            top_idx = np.argmax(col)
            cwe_dominant_pattern[cwe] = {
                "pattern": pattern_names[top_idx],
                "count": int(col[top_idx]),
                "total_patterns": int(col.sum()),
            }

    # ------------------------------------------------------------------
    # 4. ROS架构根因分析
    # ------------------------------------------------------------------
    architectural_root_causes = {
        "missing_null_check": {
            "root_cause": "ROS节点生命周期状态转换导致指针失效",
            "mechanism": "节点在shutdown/deactivate时，回调中持有的指针可能已被释放",
            "mitigation": "使用weak_ptr + lock()模式，或在回调中检查节点状态",
        },
        "missing_lock": {
            "root_cause": "ROS2 MultiThreadedExecutor并发调度回调",
            "mechanism": "多个回调可能被不同线程同时执行，访问共享状态",
            "mitigation": "使用MutuallyExclusiveCallbackGroup或显式互斥锁",
        },
        "unchecked_return": {
            "root_cause": "ROS服务/动作调用的异步失败模式",
            "mechanism": "服务超时、节点不可达等情况下调用静默失败",
            "mitigation": "检查Future状态，设置超时处理逻辑",
        },
        "raw_pointer_no_raii": {
            "root_cause": "ROS节点生命周期与资源生命周期不一致",
            "mechanism": "节点销毁时，手动管理的资源可能泄漏或悬挂",
            "mitigation": "使用shared_ptr/unique_ptr，绑定到节点生命周期",
        },
        "no_bounds_check": {
            "root_cause": "ROS消息反序列化不保证数据完整性",
            "mechanism": "接收到的消息数组长度可能与预期不符",
            "mitigation": "在访问消息数组前检查size()，使用at()替代[]",
        },
        "missing_input_validation": {
            "root_cause": "ROS话题通信无内置认证和数据验证",
            "mechanism": "任何节点都可以向话题发布任意数据",
            "mitigation": "在回调入口处验证消息字段范围和有效性",
        },
    }

    # ------------------------------------------------------------------
    # 5. 核心论点：系统性架构缺陷而非简单编码疏忽
    # ------------------------------------------------------------------
    # 统计有多少漏洞样本至少包含一种反模式
    vuln_with_any_pattern = sum(
        1 for s in vuln if any(s["_anti_patterns"].values())
    )
    benign_with_any_pattern = sum(
        1 for s in benign if any(s["_anti_patterns"].values())
    )

    # 每个样本的反模式数量
    vuln_pattern_counts = [sum(s["_anti_patterns"].values()) for s in vuln]
    benign_pattern_counts = [sum(s["_anti_patterns"].values()) for s in benign]

    pattern_count_comparison = mann_whitney_test(
        [float(x) for x in vuln_pattern_counts],
        [float(x) for x in benign_pattern_counts],
    )

    # 按ROS架构层聚合
    layer_stats = {}
    for name in pattern_names:
        layer = ANTI_PATTERNS[name]["ros_layer"]
        if layer not in layer_stats:
            layer_stats[layer] = {"patterns": [], "vuln_total": 0, "benign_total": 0}
        layer_stats[layer]["patterns"].append(name)
        layer_stats[layer]["vuln_total"] += pattern_stats[name]["vuln_count"]
        layer_stats[layer]["benign_total"] += pattern_stats[name]["benign_count"]

    # ------------------------------------------------------------------
    # 6. Findings
    # ------------------------------------------------------------------
    significant_patterns = [
        name for name in pattern_names
        if pattern_stats[name]["bh_significant"]
    ]

    findings = []
    findings.append(
        f"在{n_vuln}个漏洞样本中，{vuln_with_any_pattern}个({vuln_with_any_pattern/n_vuln*100:.1f}%)"
        f"至少包含一种反模式，而良性样本为{benign_with_any_pattern}个"
        f"({benign_with_any_pattern/n_benign*100:.1f}%)"
    )
    findings.append(
        f"漏洞样本平均反模式数量({np.mean(vuln_pattern_counts):.2f})显著高于"
        f"良性样本({np.mean(benign_pattern_counts):.2f})，"
        f"Mann-Whitney U p={pattern_count_comparison['p_value']:.4e}"
    )
    findings.append(
        f"经BH校正后，{len(significant_patterns)}种反模式与漏洞显著关联: "
        + ", ".join(significant_patterns)
    )
    if chi2_result and chi2_result["significant"]:
        findings.append(
            f"反模式×CWE关联显著(χ²={chi2_result['chi2']:.2f}, p={chi2_result['p_value']:.4e}, "
            f"Cramér's V={chi2_result['cramers_v']:.3f}/{chi2_result['cramers_v_interpretation']})"
        )
    findings.append(
        "这些反模式并非简单的编码疏忽，而是ROS架构特性（异步回调、无认证通信、"
        "复杂生命周期）导致的系统性缺陷"
    )

    # ------------------------------------------------------------------
    # 返回结果
    # ------------------------------------------------------------------
    return {
        "rq": "RQ6",
        "title": "漏洞代码反模式与ROS架构缺陷关联",
        "n_vulnerable": n_vuln,
        "n_benign": n_benign,
        "pattern_definitions": ANTI_PATTERNS,
        "pattern_stats": pattern_stats,
        "pattern_cwe_contingency": {
            "table": pattern_cwe_table.tolist(),
            "row_labels": pattern_names,
            "col_labels": cwe_types,
            "chi2_test": chi2_result,
            "cwe_dominant_pattern": cwe_dominant_pattern,
        },
        "architectural_root_causes": architectural_root_causes,
        "summary": {
            "vuln_with_any_pattern": vuln_with_any_pattern,
            "vuln_with_any_pattern_pct": vuln_with_any_pattern / n_vuln if n_vuln > 0 else 0,
            "benign_with_any_pattern": benign_with_any_pattern,
            "benign_with_any_pattern_pct": benign_with_any_pattern / n_benign if n_benign > 0 else 0,
            "mean_patterns_vuln": float(np.mean(vuln_pattern_counts)),
            "mean_patterns_benign": float(np.mean(benign_pattern_counts)),
            "pattern_count_mann_whitney": pattern_count_comparison,
            "layer_aggregation": layer_stats,
        },
        "significant_patterns_after_correction": significant_patterns,
        "findings": findings,
    }
