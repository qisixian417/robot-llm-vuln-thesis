# [D-RQ3] 代码复杂度与漏洞相关性：7个指标Mann-Whitney U检验+Cliff's delta+Holm校正
"""
RQ3: 代码复杂度与漏洞相关性
分析7个复杂度指标在漏洞/良性样本间的差异，多重比较校正，相关性矩阵，逻辑回归
"""
import numpy as np
from scipy import stats as scipy_stats
from typing import Dict, List

from .config import *
from .statistical_utils import *
from .data_loader import split_by_label, compute_code_metrics


# 7个核心复杂度指标
METRIC_NAMES = [
    "loc", "sloc", "num_functions_called", "max_nesting_depth",
    "num_conditions", "cyclomatic_complexity", "num_pointers",
]


def rq3_code_complexity(samples: List[Dict]) -> Dict:
    """
    RQ3完整分析：代码复杂度与漏洞相关性

    Returns:
        包含所有分析结果的字典
    """
    vuln, benign = split_by_label(samples)

    if len(vuln) < 3 or len(benign) < 3:
        return {"error": "Insufficient samples for analysis (need >= 3 per group)"}

    # Extract metric values for each group
    vuln_metrics = {m: [s["_metrics"][m] for s in vuln] for m in METRIC_NAMES}
    benign_metrics = {m: [s["_metrics"][m] for s in benign] for m in METRIC_NAMES}

    # ========================================================================
    # 1 & 2. Per-metric comparison: mean, median, Mann-Whitney U, Cliff's delta,
    #         Bootstrap CI, Cohen's d, Vargha-Delaney A
    # ========================================================================
    metric_comparisons = {}
    raw_p_values = []

    for metric in METRIC_NAMES:
        v_vals = vuln_metrics[metric]
        b_vals = benign_metrics[metric]

        v_arr = np.array(v_vals, dtype=float)
        b_arr = np.array(b_vals, dtype=float)

        # Descriptive statistics
        v_mean = float(np.mean(v_arr))
        v_median = float(np.median(v_arr))
        v_std = float(np.std(v_arr, ddof=1)) if len(v_arr) > 1 else 0.0
        b_mean = float(np.mean(b_arr))
        b_median = float(np.median(b_arr))
        b_std = float(np.std(b_arr, ddof=1)) if len(b_arr) > 1 else 0.0

        # Mann-Whitney U test
        mw_result = mann_whitney_test(v_vals, b_vals)
        raw_p_values.append(mw_result["p_value"] if mw_result["p_value"] is not None else 1.0)

        # Cliff's delta with Bootstrap CI
        cd_point, cd_lower, cd_upper = cliff_delta_bootstrap_ci(
            v_vals, b_vals, n_bootstrap=BOOTSTRAP_N, ci=BOOTSTRAP_CI
        )
        cd_interp = interpret_cliff_delta(cd_point)

        # Cohen's d
        cd_cohen = cohens_d(v_vals, b_vals)
        cd_cohen_interp = interpret_cohens_d(cd_cohen)

        # Vargha-Delaney A
        vda = vargha_delaney_a(v_vals, b_vals)

        metric_comparisons[metric] = {
            "vulnerable": {
                "mean": v_mean,
                "median": v_median,
                "std": v_std,
                "n": len(v_vals),
            },
            "benign": {
                "mean": b_mean,
                "median": b_median,
                "std": b_std,
                "n": len(b_vals),
            },
            "mann_whitney": {
                "u_statistic": mw_result["u_statistic"],
                "p_value": mw_result["p_value"],
                "significant": mw_result["significant"],
            },
            "cliff_delta": {
                "value": cd_point,
                "ci_lower": cd_lower,
                "ci_upper": cd_upper,
                "interpretation": cd_interp,
            },
            "cohens_d": {
                "value": cd_cohen,
                "interpretation": cd_cohen_interp,
            },
            "vargha_delaney_a": vda,
        }

    # ========================================================================
    # 3. Holm-Bonferroni correction for all 7 p-values
    # ========================================================================
    corrected_results = holm_bonferroni(raw_p_values)

    for i, metric in enumerate(METRIC_NAMES):
        adj_p, sig = corrected_results[i]
        metric_comparisons[metric]["mann_whitney"]["p_adjusted"] = adj_p
        metric_comparisons[metric]["mann_whitney"]["significant_adjusted"] = sig

    # ========================================================================
    # 4. Spearman correlation matrix (multicollinearity check)
    # ========================================================================
    # Build matrix from ALL samples
    all_metric_values = np.zeros((len(samples), len(METRIC_NAMES)))
    for i, s in enumerate(samples):
        for j, metric in enumerate(METRIC_NAMES):
            all_metric_values[i, j] = s["_metrics"][metric]

    correlation_matrix = np.zeros((len(METRIC_NAMES), len(METRIC_NAMES)))
    correlation_p_matrix = np.zeros((len(METRIC_NAMES), len(METRIC_NAMES)))

    for i in range(len(METRIC_NAMES)):
        for j in range(len(METRIC_NAMES)):
            if i == j:
                correlation_matrix[i, j] = 1.0
                correlation_p_matrix[i, j] = 0.0
            else:
                rho, p_val = scipy_stats.spearmanr(
                    all_metric_values[:, i], all_metric_values[:, j]
                )
                correlation_matrix[i, j] = rho
                correlation_p_matrix[i, j] = p_val

    # Identify highly correlated pairs (|rho| > 0.7)
    high_correlation_pairs = []
    for i in range(len(METRIC_NAMES)):
        for j in range(i + 1, len(METRIC_NAMES)):
            if abs(correlation_matrix[i, j]) > 0.7:
                high_correlation_pairs.append({
                    "metric_1": METRIC_NAMES[i],
                    "metric_2": METRIC_NAMES[j],
                    "rho": float(correlation_matrix[i, j]),
                    "p_value": float(correlation_p_matrix[i, j]),
                })

    spearman_correlation = {
        "matrix": correlation_matrix.tolist(),
        "p_matrix": correlation_p_matrix.tolist(),
        "metric_names": METRIC_NAMES,
        "high_correlation_pairs": high_correlation_pairs,
        "multicollinearity_warning": len(high_correlation_pairs) > 0,
    }

    # ========================================================================
    # 5. Logistic regression
    # ========================================================================
    logistic_regression = _run_logistic_regression(samples, METRIC_NAMES)

    # ========================================================================
    # 6. Findings
    # ========================================================================
    findings = []

    # Significant metrics after correction
    sig_metrics = [
        m for m in METRIC_NAMES
        if metric_comparisons[m]["mann_whitney"]["significant_adjusted"]
    ]
    if sig_metrics:
        findings.append(
            f"经Holm-Bonferroni校正后，{len(sig_metrics)}个指标在漏洞/良性样本间"
            f"存在显著差异：{', '.join(sig_metrics)}"
        )
    else:
        findings.append("经Holm-Bonferroni校正后，无指标达到统计显著性")

    # Largest effect sizes
    effect_sizes = [
        (m, abs(metric_comparisons[m]["cliff_delta"]["value"]))
        for m in METRIC_NAMES
    ]
    effect_sizes.sort(key=lambda x: x[1], reverse=True)
    top_effect = effect_sizes[0]
    findings.append(
        f"效应量最大的指标是 {top_effect[0]}（Cliff's δ = "
        f"{metric_comparisons[top_effect[0]]['cliff_delta']['value']:.3f}，"
        f"{metric_comparisons[top_effect[0]]['cliff_delta']['interpretation']}效应）"
    )

    # Multicollinearity
    if high_correlation_pairs:
        pair_strs = [
            f"{p['metric_1']}-{p['metric_2']}(ρ={p['rho']:.2f})"
            for p in high_correlation_pairs[:3]
        ]
        findings.append(
            f"存在多重共线性风险：{', '.join(pair_strs)}"
        )

    # Logistic regression summary
    if logistic_regression.get("auc_mean") is not None:
        findings.append(
            f"逻辑回归5折交叉验证AUC = {logistic_regression['auc_mean']:.3f} "
            f"(±{logistic_regression['auc_std']:.3f})，"
            f"伪R² = {logistic_regression.get('pseudo_r2', 0):.3f}"
        )

    # Direction of effect for significant metrics
    for m in sig_metrics[:3]:
        v_med = metric_comparisons[m]["vulnerable"]["median"]
        b_med = metric_comparisons[m]["benign"]["median"]
        direction = "高于" if v_med > b_med else "低于"
        findings.append(
            f"漏洞样本的 {m} 中位数（{v_med:.1f}）{direction}良性样本（{b_med:.1f}）"
        )

    # ========================================================================
    # 汇总返回
    # ========================================================================
    return {
        "n_vulnerable": len(vuln),
        "n_benign": len(benign),
        "metrics_analyzed": METRIC_NAMES,
        "metric_comparisons": metric_comparisons,
        "holm_bonferroni_correction": {
            "raw_p_values": raw_p_values,
            "adjusted_results": [
                {"metric": m, "p_adjusted": corrected_results[i][0],
                 "significant": corrected_results[i][1]}
                for i, m in enumerate(METRIC_NAMES)
            ],
        },
        "spearman_correlation": spearman_correlation,
        "logistic_regression": logistic_regression,
        "findings": findings,
    }


def _run_logistic_regression(samples: List[Dict], metric_names: List[str]) -> Dict:
    """
    逻辑回归分析：预测漏洞标签

    使用sklearn LogisticRegression + 5折分层交叉验证
    """
    try:
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import StratifiedKFold, cross_val_score
        from sklearn.preprocessing import StandardScaler
        from sklearn.metrics import roc_auc_score
    except ImportError:
        return {
            "error": "sklearn not available",
            "note": "Install scikit-learn to run logistic regression analysis",
        }

    # Prepare feature matrix and labels
    X = np.zeros((len(samples), len(metric_names)))
    y = np.zeros(len(samples), dtype=int)

    for i, s in enumerate(samples):
        for j, metric in enumerate(metric_names):
            X[i, j] = s["_metrics"][metric]
        y[i] = s["_label"]

    # Check for sufficient class balance
    n_pos = np.sum(y == 1)
    n_neg = np.sum(y == 0)
    if n_pos < CV_FOLDS or n_neg < CV_FOLDS:
        return {
            "error": f"Insufficient samples per class for {CV_FOLDS}-fold CV "
                     f"(vuln={n_pos}, benign={n_neg})",
        }

    # Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Fit full model for coefficients
    model = LogisticRegression(
        max_iter=1000, solver="lbfgs", random_state=42, penalty="l2"
    )
    model.fit(X_scaled, y)

    # Coefficients and their significance (Wald test approximation)
    coefficients = {}
    coefs = model.coef_[0]
    intercept = model.intercept_[0]

    # Approximate standard errors via Hessian
    probas = model.predict_proba(X_scaled)[:, 1]
    W = np.diag(probas * (1 - probas))
    # X_aug includes intercept
    X_aug = np.hstack([np.ones((X_scaled.shape[0], 1)), X_scaled])

    try:
        # Fisher information matrix
        XWX = X_aug.T @ W @ X_aug
        cov_matrix = np.linalg.inv(XWX)
        se = np.sqrt(np.diag(cov_matrix))
        se_coefs = se[1:]  # exclude intercept SE

        for j, metric in enumerate(metric_names):
            z_val = coefs[j] / se_coefs[j] if se_coefs[j] > 0 else 0.0
            p_val = 2 * (1 - scipy_stats.norm.cdf(abs(z_val)))
            coefficients[metric] = {
                "coefficient": float(coefs[j]),
                "std_error": float(se_coefs[j]),
                "z_value": float(z_val),
                "p_value": float(p_val),
                "significant": p_val < ALPHA,
                "odds_ratio": float(np.exp(coefs[j])),
            }
    except np.linalg.LinAlgError:
        # Fallback: report coefficients without p-values
        for j, metric in enumerate(metric_names):
            coefficients[metric] = {
                "coefficient": float(coefs[j]),
                "std_error": None,
                "z_value": None,
                "p_value": None,
                "significant": None,
                "odds_ratio": float(np.exp(coefs[j])),
            }

    # Pseudo R-squared (McFadden)
    log_likelihood = np.sum(
        y * np.log(probas + 1e-10) + (1 - y) * np.log(1 - probas + 1e-10)
    )
    base_prob = np.mean(y)
    log_likelihood_null = np.sum(
        y * np.log(base_prob + 1e-10) + (1 - y) * np.log(1 - base_prob + 1e-10)
    )
    pseudo_r2 = 1 - (log_likelihood / log_likelihood_null) if log_likelihood_null != 0 else 0.0

    # AUC on full data
    auc_full = roc_auc_score(y, probas)

    # 5-fold stratified cross-validation AUC
    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=42)
    cv_scores = cross_val_score(
        LogisticRegression(max_iter=1000, solver="lbfgs", random_state=42, penalty="l2"),
        X_scaled, y, cv=cv, scoring="roc_auc"
    )

    return {
        "coefficients": coefficients,
        "intercept": float(intercept),
        "pseudo_r2": float(pseudo_r2),
        "auc_full_data": float(auc_full),
        "auc_mean": float(np.mean(cv_scores)),
        "auc_std": float(np.std(cv_scores)),
        "auc_per_fold": cv_scores.tolist(),
        "cv_folds": CV_FOLDS,
        "n_samples": len(samples),
        "n_features": len(metric_names),
        "feature_names": metric_names,
        "scaler_means": scaler.mean_.tolist(),
        "scaler_stds": scaler.scale_.tolist(),
    }
