# [实证分析] 统计工具库：Mann-Whitney U/Fisher/卡方/Cliff's delta/Cohen's d/Cramér's V等
"""
统计工具函数：Bootstrap CI、效应量、多重比较校正、假设检验
"""
import math
import numpy as np
from scipy import stats as scipy_stats
from typing import List, Tuple, Dict, Optional


# ============================================================================
# Bootstrap 置信区间
# ============================================================================

def bootstrap_ci(data: np.ndarray, statistic_func=np.mean, n_bootstrap: int = 10000,
                 ci: float = 0.95, method: str = "bca") -> Tuple[float, float, float]:
    """
    计算Bootstrap置信区间（BCa方法）

    Returns: (point_estimate, ci_lower, ci_upper)
    """
    data = np.asarray(data)
    n = len(data)
    if n == 0:
        return (0.0, 0.0, 0.0)

    point_estimate = statistic_func(data)

    # Bootstrap重采样
    rng = np.random.default_rng(42)
    boot_stats = np.array([
        statistic_func(data[rng.integers(0, n, size=n)])
        for _ in range(n_bootstrap)
    ])

    alpha = 1 - ci
    if method == "percentile":
        ci_lower = np.percentile(boot_stats, 100 * alpha / 2)
        ci_upper = np.percentile(boot_stats, 100 * (1 - alpha / 2))
    elif method == "bca":
        # BCa校正
        # 偏差校正因子 z0
        z0 = scipy_stats.norm.ppf(np.mean(boot_stats < point_estimate))

        # 加速因子 a (jackknife)
        jackknife_stats = np.array([
            statistic_func(np.delete(data, i))
            for i in range(n)
        ])
        jack_mean = np.mean(jackknife_stats)
        numerator = np.sum((jack_mean - jackknife_stats) ** 3)
        denominator = 6 * (np.sum((jack_mean - jackknife_stats) ** 2) ** 1.5)

        a = numerator / denominator if denominator != 0 else 0

        # 调整百分位数
        z_alpha_lower = scipy_stats.norm.ppf(alpha / 2)
        z_alpha_upper = scipy_stats.norm.ppf(1 - alpha / 2)

        def adjusted_percentile(z_alpha):
            numer = z0 + z_alpha
            adjusted = z0 + numer / (1 - a * numer)
            return scipy_stats.norm.cdf(adjusted) * 100

        ci_lower = np.percentile(boot_stats, adjusted_percentile(z_alpha_lower))
        ci_upper = np.percentile(boot_stats, adjusted_percentile(z_alpha_upper))
    else:
        ci_lower = np.percentile(boot_stats, 100 * alpha / 2)
        ci_upper = np.percentile(boot_stats, 100 * (1 - alpha / 2))

    return (float(point_estimate), float(ci_lower), float(ci_upper))


def bootstrap_proportion_ci(successes: int, total: int, n_bootstrap: int = 10000,
                            ci: float = 0.95) -> Tuple[float, float, float]:
    """计算比例的Bootstrap置信区间"""
    if total == 0:
        return (0.0, 0.0, 0.0)
    data = np.array([1] * successes + [0] * (total - successes))
    return bootstrap_ci(data, statistic_func=np.mean, n_bootstrap=n_bootstrap, ci=ci)


def wilson_score_ci(successes: int, total: int, ci: float = 0.95) -> Tuple[float, float, float]:
    """Wilson score置信区间（小样本比例更准确）"""
    if total == 0:
        return (0.0, 0.0, 0.0)
    p = successes / total
    z = scipy_stats.norm.ppf(1 - (1 - ci) / 2)
    denominator = 1 + z**2 / total
    center = (p + z**2 / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z**2 / (4 * total**2)) / denominator
    return (float(p), float(center - margin), float(center + margin))


# ============================================================================
# 效应量计算
# ============================================================================

def cliff_delta(group1: List[float], group2: List[float]) -> float:
    """计算Cliff's Delta效应量（非参数）"""
    g1 = np.asarray(group1)
    g2 = np.asarray(group2)
    if len(g1) == 0 or len(g2) == 0:
        return 0.0

    n1, n2 = len(g1), len(g2)
    dominance = 0
    for x in g1:
        dominance += np.sum(x > g2) - np.sum(x < g2)
    return float(dominance / (n1 * n2))


def cliff_delta_bootstrap_ci(group1: List[float], group2: List[float],
                             n_bootstrap: int = 10000, ci: float = 0.95) -> Tuple[float, float, float]:
    """Cliff's Delta + Bootstrap CI"""
    g1 = np.asarray(group1)
    g2 = np.asarray(group2)
    if len(g1) == 0 or len(g2) == 0:
        return (0.0, 0.0, 0.0)

    point = cliff_delta(group1, group2)

    rng = np.random.default_rng(42)
    boot_deltas = []
    for _ in range(n_bootstrap):
        b1 = g1[rng.integers(0, len(g1), size=len(g1))]
        b2 = g2[rng.integers(0, len(g2), size=len(g2))]
        d = 0
        for x in b1:
            d += np.sum(x > b2) - np.sum(x < b2)
        boot_deltas.append(d / (len(b1) * len(b2)))

    alpha = 1 - ci
    ci_lower = np.percentile(boot_deltas, 100 * alpha / 2)
    ci_upper = np.percentile(boot_deltas, 100 * (1 - alpha / 2))
    return (float(point), float(ci_lower), float(ci_upper))


def vargha_delaney_a(group1: List[float], group2: List[float]) -> float:
    """Vargha-Delaney A效应量（更直观：P(X1 > X2)）"""
    g1 = np.asarray(group1)
    g2 = np.asarray(group2)
    if len(g1) == 0 or len(g2) == 0:
        return 0.5

    n1, n2 = len(g1), len(g2)
    r = scipy_stats.rankdata(np.concatenate([g1, g2]))
    r1 = r[:n1]
    a = (np.sum(r1) - n1 * (n1 + 1) / 2) / (n1 * n2)
    return float(a)


def cohens_d(group1: List[float], group2: List[float]) -> float:
    """计算Cohen's d效应量"""
    g1 = np.asarray(group1, dtype=float)
    g2 = np.asarray(group2, dtype=float)
    if len(g1) == 0 or len(g2) == 0:
        return 0.0

    n1, n2 = len(g1), len(g2)
    mean1, mean2 = np.mean(g1), np.mean(g2)
    std1, std2 = np.std(g1, ddof=1), np.std(g2, ddof=1)

    pooled_std = np.sqrt(((n1 - 1) * std1**2 + (n2 - 1) * std2**2) / (n1 + n2 - 2))
    if pooled_std == 0:
        return 0.0
    return float((mean1 - mean2) / pooled_std)


def cramers_v(contingency_table: np.ndarray) -> float:
    """计算Cramér's V关联强度（带偏差校正）"""
    chi2, _, _, _ = scipy_stats.chi2_contingency(contingency_table)
    n = np.sum(contingency_table)
    r, k = contingency_table.shape
    min_dim = min(r - 1, k - 1)
    if n == 0 or min_dim == 0:
        return 0.0

    # 偏差校正公式
    phi2 = chi2 / n
    phi2_corrected = max(0, phi2 - (r - 1) * (k - 1) / (n - 1))
    r_corrected = r - (r - 1)**2 / (n - 1)
    k_corrected = k - (k - 1)**2 / (n - 1)
    min_corrected = min(r_corrected - 1, k_corrected - 1)

    if min_corrected <= 0:
        return float(np.sqrt(phi2 / min_dim))
    return float(np.sqrt(phi2_corrected / min_corrected))


def odds_ratio_ci(a: int, b: int, c: int, d: int,
                  ci: float = 0.95) -> Tuple[float, float, float]:
    """
    计算Odds Ratio及其置信区间
    2x2表: [[a, b], [c, d]]
    OR = (a*d) / (b*c)
    """
    a_, b_, c_, d_ = a + 0.5, b + 0.5, c + 0.5, d + 0.5
    or_val = (a_ * d_) / (b_ * c_)
    log_or = math.log(or_val)
    se_log_or = math.sqrt(1/a_ + 1/b_ + 1/c_ + 1/d_)

    z = scipy_stats.norm.ppf(1 - (1 - ci) / 2)
    ci_lower = math.exp(log_or - z * se_log_or)
    ci_upper = math.exp(log_or + z * se_log_or)

    return (float(or_val), float(ci_lower), float(ci_upper))


# ============================================================================
# 效应量解释
# ============================================================================

def interpret_cliff_delta(d: float) -> str:
    d_abs = abs(d)
    if d_abs < 0.147:
        return "negligible"
    elif d_abs < 0.33:
        return "small"
    elif d_abs < 0.474:
        return "medium"
    else:
        return "large"


def interpret_cohens_d(d: float) -> str:
    d_abs = abs(d)
    if d_abs < 0.2:
        return "negligible"
    elif d_abs < 0.5:
        return "small"
    elif d_abs < 0.8:
        return "medium"
    else:
        return "large"


def interpret_cramers_v(v: float) -> str:
    if v < 0.1:
        return "negligible"
    elif v < 0.3:
        return "small"
    elif v < 0.5:
        return "medium"
    else:
        return "large"


# ============================================================================
# 多重比较校正
# ============================================================================

def holm_bonferroni(p_values: List[float]) -> List[Tuple[float, bool]]:
    """
    Holm-Bonferroni逐步校正法
    Returns: [(adjusted_p, significant), ...]
    """
    n = len(p_values)
    if n == 0:
        return []

    sorted_indices = np.argsort(p_values)
    adjusted = [0.0] * n
    significant = [False] * n

    max_adj = 0.0
    for rank, idx in enumerate(sorted_indices):
        adj_p = p_values[idx] * (n - rank)
        adj_p = min(adj_p, 1.0)
        max_adj = max(max_adj, adj_p)
        adjusted[idx] = max_adj
        significant[idx] = max_adj < 0.05

    return list(zip(adjusted, significant))


def benjamini_hochberg(p_values: List[float]) -> List[Tuple[float, bool]]:
    """
    Benjamini-Hochberg FDR校正
    Returns: [(adjusted_p, significant), ...]
    """
    n = len(p_values)
    if n == 0:
        return []

    sorted_indices = np.argsort(p_values)
    adjusted = [0.0] * n

    min_adj = 1.0
    for rank in range(n - 1, -1, -1):
        idx = sorted_indices[rank]
        adj_p = p_values[idx] * n / (rank + 1)
        adj_p = min(adj_p, 1.0)
        min_adj = min(min_adj, adj_p)
        adjusted[idx] = min_adj

    significant = [p < 0.05 for p in adjusted]
    return list(zip(adjusted, significant))


# ============================================================================
# 假设检验辅助
# ============================================================================

def mann_whitney_test(group1: List[float], group2: List[float]) -> Dict:
    """Mann-Whitney U检验 + 效应量"""
    g1 = np.asarray(group1)
    g2 = np.asarray(group2)

    if len(g1) < 3 or len(g2) < 3:
        return {"u_statistic": None, "p_value": None, "significant": None,
                "cliff_delta": 0.0, "vargha_delaney_a": 0.5}

    u_stat, p_val = scipy_stats.mannwhitneyu(g1, g2, alternative='two-sided')
    cd = cliff_delta(group1, group2)
    vda = vargha_delaney_a(group1, group2)

    return {
        "u_statistic": float(u_stat),
        "p_value": float(p_val),
        "significant": p_val < 0.05,
        "cliff_delta": cd,
        "cliff_delta_interpretation": interpret_cliff_delta(cd),
        "vargha_delaney_a": vda,
    }


def fisher_exact_test(table_2x2: List[List[int]]) -> Dict:
    """Fisher's exact test for 2x2 table"""
    table = np.array(table_2x2)
    odds_ratio, p_value = scipy_stats.fisher_exact(table)
    a, b, c, d = table[0][0], table[0][1], table[1][0], table[1][1]
    or_val, or_lower, or_upper = odds_ratio_ci(a, b, c, d)

    return {
        "odds_ratio": float(odds_ratio),
        "p_value": float(p_value),
        "significant": p_value < 0.05,
        "or_ci_lower": or_lower,
        "or_ci_upper": or_upper,
    }


def proportion_z_test(count1: int, total1: int, count2: int, total2: int) -> Dict:
    """两比例z检验"""
    if total1 == 0 or total2 == 0:
        return {"z_statistic": None, "p_value": None, "significant": None}

    p1 = count1 / total1
    p2 = count2 / total2
    p_pool = (count1 + count2) / (total1 + total2)

    se = math.sqrt(p_pool * (1 - p_pool) * (1/total1 + 1/total2))
    if se == 0:
        return {"z_statistic": 0.0, "p_value": 1.0, "significant": False}

    z = (p1 - p2) / se
    p_value = 2 * (1 - scipy_stats.norm.cdf(abs(z)))

    return {
        "z_statistic": float(z),
        "p_value": float(p_value),
        "significant": p_value < 0.05,
        "proportion_1": float(p1),
        "proportion_2": float(p2),
        "difference": float(p1 - p2),
    }


# ============================================================================
# 多样性指标
# ============================================================================

def shannon_entropy(counts: List[int]) -> float:
    """Shannon熵"""
    total = sum(counts)
    if total == 0:
        return 0.0
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def gini_simpson(counts: List[int]) -> float:
    """Gini-Simpson多样性指数 (1 - sum(p_i^2))"""
    total = sum(counts)
    if total == 0:
        return 0.0
    return 1.0 - sum((c / total) ** 2 for c in counts)


def gini_coefficient(values: List[float]) -> float:
    """Gini系数（衡量集中度，0=完全均匀，1=完全集中）"""
    values = np.array(sorted(values), dtype=float)
    n = len(values)
    if n == 0 or np.sum(values) == 0:
        return 0.0
    index = np.arange(1, n + 1)
    return float((2 * np.sum(index * values) / (n * np.sum(values))) - (n + 1) / n)


# ============================================================================
# PMI（点互信息）
# ============================================================================

def pointwise_mutual_information(joint_count: int, marginal_x: int,
                                  marginal_y: int, total: int) -> float:
    """计算PMI"""
    if joint_count == 0 or marginal_x == 0 or marginal_y == 0 or total == 0:
        return 0.0
    p_xy = joint_count / total
    p_x = marginal_x / total
    p_y = marginal_y / total
    return float(math.log2(p_xy / (p_x * p_y)))
