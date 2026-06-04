# [D-RQ6] 仓库集中度分析：Gini系数/Lorenz曲线，发现Top 10仓库占91.2%漏洞
"""
RQ8: 仓库级漏洞集中度分析
分析漏洞在不同仓库间的分布集中度、CWE特化、规模与密度的关系
"""
import numpy as np
from collections import Counter, defaultdict
from typing import Dict, List
from scipy import stats as scipy_stats

from .config import *
from .statistical_utils import *
from .data_loader import split_by_label


# ============================================================================
# 主分析函数
# ============================================================================

def rq8_repository_analysis(samples: List[Dict]) -> Dict:
    """
    RQ8: 仓库级漏洞集中度分析

    Returns:
        包含仓库统计、Gini系数、Top仓库分析、Spearman相关的完整分析字典
    """
    vuln, benign = split_by_label(samples)
    n_vuln = len(vuln)
    n_total = len(samples)

    # ------------------------------------------------------------------
    # 1. 每个仓库的统计
    # ------------------------------------------------------------------
    repo_total = Counter(s["_repo"] for s in samples)
    repo_vuln = Counter(s["_repo"] for s in vuln)

    repo_stats = {}
    for repo in repo_total:
        total = repo_total[repo]
        vuln_count = repo_vuln.get(repo, 0)
        density = vuln_count / total if total > 0 else 0
        repo_stats[repo] = {
            "total_samples": total,
            "vulnerable_count": vuln_count,
            "benign_count": total - vuln_count,
            "vulnerability_density": density,
            "density_ci": wilson_score_ci(vuln_count, total),
        }

    n_repos = len(repo_stats)

    # ------------------------------------------------------------------
    # 2. Gini系数（漏洞集中度）
    # ------------------------------------------------------------------
    vuln_counts_per_repo = [repo_stats[r]["vulnerable_count"] for r in repo_stats]
    gini = gini_coefficient([float(x) for x in vuln_counts_per_repo])

    # 也计算基于密度的Gini
    densities = [repo_stats[r]["vulnerability_density"] for r in repo_stats]
    gini_density = gini_coefficient(densities)

    # ------------------------------------------------------------------
    # 3. Top 10 仓库（按漏洞数量）
    # ------------------------------------------------------------------
    sorted_repos = sorted(repo_stats.items(),
                          key=lambda x: x[1]["vulnerable_count"], reverse=True)
    top_10_repos = []
    for repo, stats in sorted_repos[:10]:
        top_10_repos.append({
            "repo": repo,
            "vulnerable_count": stats["vulnerable_count"],
            "total_samples": stats["total_samples"],
            "density": stats["vulnerability_density"],
            "pct_of_all_vulns": stats["vulnerable_count"] / n_vuln * 100 if n_vuln > 0 else 0,
        })

    # 累积占比
    cumulative_pct = 0
    for entry in top_10_repos:
        cumulative_pct += entry["pct_of_all_vulns"]
        entry["cumulative_pct"] = cumulative_pct

    # ------------------------------------------------------------------
    # 4. Top 5 仓库的CWE profile对比
    # ------------------------------------------------------------------
    top_5_repos_names = [entry["repo"] for entry in top_10_repos[:5]]
    all_cwe_types = sorted(set(s["_cwe"] for s in vuln if s["_cwe"] != "unknown"))

    repo_cwe_profiles = {}
    for repo in top_5_repos_names:
        repo_vuln_samples = [s for s in vuln if s["_repo"] == repo]
        cwe_counter = Counter(s["_cwe"] for s in repo_vuln_samples if s["_cwe"] != "unknown")
        total_repo_vuln = len(repo_vuln_samples)

        profile = {}
        for cwe in all_cwe_types:
            count = cwe_counter.get(cwe, 0)
            profile[cwe] = {
                "count": count,
                "percentage": count / total_repo_vuln * 100 if total_repo_vuln > 0 else 0,
            }

        # 找出该仓库的主导CWE
        if cwe_counter:
            dominant_cwe = cwe_counter.most_common(1)[0]
            profile["_dominant"] = {
                "cwe": dominant_cwe[0],
                "count": dominant_cwe[1],
                "percentage": dominant_cwe[1] / total_repo_vuln * 100 if total_repo_vuln > 0 else 0,
            }
        else:
            profile["_dominant"] = {"cwe": "unknown", "count": 0, "percentage": 0}

        repo_cwe_profiles[repo] = profile

    # ------------------------------------------------------------------
    # 5. Spearman相关：仓库样本量 vs 漏洞密度
    # ------------------------------------------------------------------
    repo_sizes = [repo_stats[r]["total_samples"] for r in repo_stats]
    repo_densities = [repo_stats[r]["vulnerability_density"] for r in repo_stats]

    spearman_result = None
    if len(repo_sizes) >= 3:
        rho, p_value = scipy_stats.spearmanr(repo_sizes, repo_densities)
        spearman_result = {
            "rho": float(rho),
            "p_value": float(p_value),
            "significant": p_value < ALPHA,
            "interpretation": (
                "正相关：较大仓库漏洞密度更高" if rho > 0.3 and p_value < ALPHA
                else "负相关：较大仓库漏洞密度更低" if rho < -0.3 and p_value < ALPHA
                else "无显著线性关联：仓库规模与漏洞密度无明显关系"
            ),
        }

    # ------------------------------------------------------------------
    # 6. Repo × CWE特化：Top 5仓库 Fisher's exact test
    # ------------------------------------------------------------------
    repo_cwe_specialization = {}
    specialization_p_values = []

    for repo in top_5_repos_names:
        repo_vuln_samples = [s for s in vuln if s["_repo"] == repo]
        other_vuln_samples = [s for s in vuln if s["_repo"] != repo]

        if not repo_vuln_samples:
            continue

        # 该仓库的CWE分布
        repo_cwe_counter = Counter(
            s["_cwe"] for s in repo_vuln_samples if s["_cwe"] != "unknown"
        )
        other_cwe_counter = Counter(
            s["_cwe"] for s in other_vuln_samples if s["_cwe"] != "unknown"
        )

        # 对每种CWE做Fisher's exact test（该仓库 vs 其他仓库）
        repo_tests = {}
        repo_p_values = []

        for cwe in all_cwe_types:
            repo_with = repo_cwe_counter.get(cwe, 0)
            repo_without = len(repo_vuln_samples) - repo_with
            other_with = other_cwe_counter.get(cwe, 0)
            other_without = len(other_vuln_samples) - other_with

            if repo_with + other_with == 0:
                continue

            table = [[repo_with, repo_without],
                     [other_with, other_without]]
            test_result = fisher_exact_test(table)

            repo_tests[cwe] = {
                "repo_count": repo_with,
                "repo_pct": repo_with / len(repo_vuln_samples) * 100 if repo_vuln_samples else 0,
                "other_count": other_with,
                "other_pct": other_with / len(other_vuln_samples) * 100 if other_vuln_samples else 0,
                "fisher_test": test_result,
            }
            repo_p_values.append(test_result["p_value"])

        # BH校正
        if repo_p_values:
            bh_results = benjamini_hochberg(repo_p_values)
            cwe_keys = [k for k in repo_tests.keys()]
            for i, cwe in enumerate(cwe_keys):
                repo_tests[cwe]["bh_adjusted_p"] = bh_results[i][0]
                repo_tests[cwe]["bh_significant"] = bh_results[i][1]

        # 找出显著特化的CWE
        specialized_cwes = [
            cwe for cwe, r in repo_tests.items()
            if r.get("bh_significant", False)
        ]

        repo_cwe_specialization[repo] = {
            "tests": repo_tests,
            "specialized_cwes": specialized_cwes,
            "n_vuln_in_repo": len(repo_vuln_samples),
        }
        specialization_p_values.extend(repo_p_values)

    # ------------------------------------------------------------------
    # 7. Findings
    # ------------------------------------------------------------------
    findings = []

    findings.append(
        f"数据集涵盖{n_repos}个仓库，漏洞分布的Gini系数为{gini:.3f}，"
        f"表明漏洞高度集中在少数仓库"
    )

    if top_10_repos:
        findings.append(
            f"Top 10仓库贡献了{top_10_repos[-1]['cumulative_pct']:.1f}%的漏洞，"
            f"其中{top_10_repos[0]['repo']}最多({top_10_repos[0]['vulnerable_count']}例，"
            f"占{top_10_repos[0]['pct_of_all_vulns']:.1f}%)"
        )

    if spearman_result:
        findings.append(
            f"仓库规模与漏洞密度的Spearman相关: ρ={spearman_result['rho']:.3f}, "
            f"p={spearman_result['p_value']:.4f}。{spearman_result['interpretation']}"
        )

    # 特化仓库
    specialized_repos = [
        repo for repo, data in repo_cwe_specialization.items()
        if data["specialized_cwes"]
    ]
    if specialized_repos:
        spec_details = []
        for repo in specialized_repos:
            cwes = repo_cwe_specialization[repo]["specialized_cwes"]
            spec_details.append(f"{repo}({', '.join(cwes)})")
        findings.append(
            f"以下仓库存在CWE特化现象（与整体分布显著不同）: "
            + "; ".join(spec_details)
        )
    else:
        findings.append("Top 5仓库的CWE分布与整体无显著差异")

    findings.append(
        f"漏洞集中度(Gini={gini:.3f})表明安全审计资源应优先分配给高密度仓库"
    )

    # ------------------------------------------------------------------
    # 返回结果
    # ------------------------------------------------------------------
    return {
        "rq": "RQ8",
        "title": "仓库级漏洞集中度分析",
        "n_total_samples": n_total,
        "n_vulnerable": n_vuln,
        "n_repos": n_repos,
        "repo_stats": repo_stats,
        "concentration": {
            "gini_coefficient": gini,
            "gini_density": gini_density,
            "interpretation": (
                "高度集中" if gini > 0.6
                else "中度集中" if gini > 0.4
                else "相对均匀"
            ),
        },
        "top_10_repos": top_10_repos,
        "repo_cwe_profiles": repo_cwe_profiles,
        "spearman_size_density": spearman_result,
        "repo_cwe_specialization": repo_cwe_specialization,
        "findings": findings,
    }
