# [D-RQ5] ROS API关联分析：12种API特征PMI+Odds Ratio+BH-FDR校正，motivate ROS感知设计
"""
RQ5: ROS API特征与漏洞关联分析
- ROS特征在漏洞/良性样本中的流行度
- 特征与漏洞的关联检验（Fisher's exact + FDR校正）
- 特征×CWE的PMI矩阵
- 特征共现分析（Jaccard相似度）
- ROS架构机制归因
"""
import math
import numpy as np
from collections import Counter, defaultdict
from typing import Dict, List
from itertools import combinations

from .config import *
from .statistical_utils import *
from .data_loader import split_by_label


def rq5_ros_feature_association(samples: List[Dict]) -> Dict:
    """
    RQ5: 分析ROS API特征与漏洞的关联关系

    Args:
        samples: 预处理后的样本列表（含 _label, _cwe, _features 等字段）

    Returns:
        包含统计检验结果、PMI矩阵、共现分析和发现的字典
    """
    vuln, benign = split_by_label(samples)
    results = {}

    feature_names = list(ROS_FEATURES.keys())

    # ========================================================================
    # 1. Feature prevalence: 各特征在漏洞/良性样本中的出现频率
    # ========================================================================
    feature_prevalence = {}
    for feat in feature_names:
        vuln_present = sum(1 for s in vuln if s["_features"].get(feat, False))
        vuln_absent = len(vuln) - vuln_present
        benign_present = sum(1 for s in benign if s["_features"].get(feat, False))
        benign_absent = len(benign) - benign_present

        feature_prevalence[feat] = {
            "vuln_present": vuln_present,
            "vuln_absent": vuln_absent,
            "vuln_rate": vuln_present / len(vuln) if vuln else 0.0,
            "benign_present": benign_present,
            "benign_absent": benign_absent,
            "benign_rate": benign_present / len(benign) if benign else 0.0,
        }

    results["feature_prevalence"] = feature_prevalence

    # ========================================================================
    # 2. Fisher's exact test for each feature (feature × vuln/benign)
    # ========================================================================
    fisher_results = {}
    raw_p_values = []

    for feat in feature_names:
        fp = feature_prevalence[feat]
        # 2x2: [[feat_present_vuln, feat_present_benign],
        #        [feat_absent_vuln, feat_absent_benign]]
        table = [
            [fp["vuln_present"], fp["benign_present"]],
            [fp["vuln_absent"], fp["benign_absent"]],
        ]
        test_result = fisher_exact_test(table)
        fisher_results[feat] = {
            "table": table,
            **test_result,
        }
        raw_p_values.append(test_result["p_value"])

    results["fisher_tests"] = fisher_results

    # ========================================================================
    # 3. Odds Ratio + 95% CI for each feature
    # ========================================================================
    odds_ratios = {}
    for feat in feature_names:
        fp = feature_prevalence[feat]
        a = fp["vuln_present"]
        b = fp["benign_present"]
        c = fp["vuln_absent"]
        d = fp["benign_absent"]
        or_val, or_lower, or_upper = odds_ratio_ci(a, b, c, d)
        odds_ratios[feat] = {
            "odds_ratio": or_val,
            "ci_lower": or_lower,
            "ci_upper": or_upper,
            "risk_direction": "risk_factor" if or_val > 1 else "protective",
        }

    results["odds_ratios"] = odds_ratios

    # ========================================================================
    # 4. Benjamini-Hochberg FDR correction on all 12 p-values
    # ========================================================================
    bh_corrected = benjamini_hochberg(raw_p_values)
    fdr_results = {}
    significant_features = []

    for i, feat in enumerate(feature_names):
        adj_p, sig = bh_corrected[i]
        fdr_results[feat] = {
            "raw_p_value": raw_p_values[i],
            "adjusted_p_value": adj_p,
            "significant_after_fdr": sig,
            "odds_ratio": odds_ratios[feat]["odds_ratio"],
            "ci_lower": odds_ratios[feat]["ci_lower"],
            "ci_upper": odds_ratios[feat]["ci_upper"],
        }
        if sig:
            significant_features.append(feat)

    results["fdr_correction"] = fdr_results
    results["significant_features"] = significant_features

    # ========================================================================
    # 5. Feature × CWE PMI matrix (based on vulnerable samples only)
    # ========================================================================
    total_vuln = len(vuln)
    cwe_counts = Counter(s["_cwe"] for s in vuln)
    feature_counts_vuln = {
        feat: sum(1 for s in vuln if s["_features"].get(feat, False))
        for feat in feature_names
    }

    pmi_matrix = {}
    pmi_entries = []  # for top-20 ranking

    for feat in feature_names:
        pmi_matrix[feat] = {}
        marginal_feat = feature_counts_vuln[feat]

        for cwe, marginal_cwe in cwe_counts.items():
            # Joint count: samples that have both this feature and this CWE
            joint = sum(
                1 for s in vuln
                if s["_features"].get(feat, False) and s["_cwe"] == cwe
            )
            pmi_val = pointwise_mutual_information(joint, marginal_feat, marginal_cwe, total_vuln)
            pmi_matrix[feat][cwe] = pmi_val

            if joint > 0:
                pmi_entries.append({
                    "feature": feat,
                    "cwe": cwe,
                    "pmi": pmi_val,
                    "joint_count": joint,
                    "feature_count": marginal_feat,
                    "cwe_count": marginal_cwe,
                })

    results["pmi_matrix"] = pmi_matrix

    # ========================================================================
    # 6. Feature co-occurrence: Jaccard similarity matrix
    # ========================================================================
    # Build sets of sample indices where each feature is present
    feature_sample_sets = {}
    for feat in feature_names:
        feature_sample_sets[feat] = set(
            i for i, s in enumerate(samples) if s["_features"].get(feat, False)
        )

    jaccard_matrix = {}
    for feat_a, feat_b in combinations(feature_names, 2):
        set_a = feature_sample_sets[feat_a]
        set_b = feature_sample_sets[feat_b]
        intersection = len(set_a & set_b)
        union = len(set_a | set_b)
        jaccard = intersection / union if union > 0 else 0.0
        key = f"{feat_a}|{feat_b}"
        jaccard_matrix[key] = {
            "feature_a": feat_a,
            "feature_b": feat_b,
            "jaccard": jaccard,
            "co_occurrence_count": intersection,
            "union_count": union,
        }

    results["jaccard_matrix"] = jaccard_matrix

    # ========================================================================
    # 7. Top 20 feature-CWE associations by PMI value
    # ========================================================================
    pmi_entries_sorted = sorted(pmi_entries, key=lambda x: x["pmi"], reverse=True)
    results["top_20_pmi_associations"] = pmi_entries_sorted[:20]

    # ========================================================================
    # 8. ROS mechanism attribution: map significant features to mechanisms
    # ========================================================================
    mechanism_attribution = {}
    for feat in significant_features:
        mechanism = FEATURE_TO_MECHANISM.get(feat, "未知机制")
        mechanism_attribution[feat] = {
            "mechanism": mechanism,
            "odds_ratio": odds_ratios[feat]["odds_ratio"],
            "adjusted_p_value": fdr_results[feat]["adjusted_p_value"],
            "vuln_rate": feature_prevalence[feat]["vuln_rate"],
            "benign_rate": feature_prevalence[feat]["benign_rate"],
            "risk_direction": odds_ratios[feat]["risk_direction"],
        }

    # Also group by mechanism
    mechanism_groups = defaultdict(list)
    for feat, info in mechanism_attribution.items():
        mechanism_groups[info["mechanism"]].append({
            "feature": feat,
            **info,
        })

    results["mechanism_attribution"] = mechanism_attribution
    results["mechanism_groups"] = dict(mechanism_groups)

    # ========================================================================
    # 9. Findings
    # ========================================================================
    findings = []

    # Finding 1: Number of significant features
    findings.append({
        "id": "F5.1",
        "description": (
            f"经Benjamini-Hochberg FDR校正后，{len(significant_features)}个ROS API特征"
            f"与漏洞存在显著关联"
            + (f": {', '.join(significant_features)}" if significant_features else "")
        ),
    })

    # Finding 2: Strongest risk factors
    risk_features = [
        (feat, odds_ratios[feat]["odds_ratio"])
        for feat in significant_features
        if odds_ratios[feat]["odds_ratio"] > 1
    ]
    risk_features.sort(key=lambda x: x[1], reverse=True)
    if risk_features:
        top_risk = risk_features[0]
        findings.append({
            "id": "F5.2",
            "description": (
                f"最强风险因子为'{top_risk[0]}'特征 "
                f"(OR={top_risk[1]:.2f}, "
                f"机制: {FEATURE_TO_MECHANISM.get(top_risk[0], '未知')})"
            ),
        })

    # Finding 3: Top PMI association
    if pmi_entries_sorted:
        top_pmi = pmi_entries_sorted[0]
        findings.append({
            "id": "F5.3",
            "description": (
                f"最强特征-CWE关联: {top_pmi['feature']}×{top_pmi['cwe']} "
                f"(PMI={top_pmi['pmi']:.3f}, 共现{top_pmi['joint_count']}次)"
            ),
        })

    # Finding 4: Co-occurrence insight
    top_cooccur = sorted(
        jaccard_matrix.values(), key=lambda x: x["jaccard"], reverse=True
    )
    if top_cooccur:
        top_pair = top_cooccur[0]
        findings.append({
            "id": "F5.4",
            "description": (
                f"最高共现特征对: {top_pair['feature_a']}与{top_pair['feature_b']} "
                f"(Jaccard={top_pair['jaccard']:.3f}, "
                f"共现{top_pair['co_occurrence_count']}个样本)"
            ),
        })

    # Finding 5: Mechanism-level summary
    if mechanism_groups:
        mechanism_summary = ", ".join(
            f"{mech}({len(feats)}个特征)"
            for mech, feats in mechanism_groups.items()
        )
        findings.append({
            "id": "F5.5",
            "description": f"显著特征涉及的ROS架构机制: {mechanism_summary}",
        })

    results["findings"] = findings

    return results
