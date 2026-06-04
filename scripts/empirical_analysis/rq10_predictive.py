# [C-RQ2] 预测建模：逻辑回归+随机森林5折交叉验证，AUC=0.94作为非LLM ML基线
"""
RQ10: 漏洞可预测性建模
逻辑回归、交叉验证、特征重要性、随机森林对比
"""
import numpy as np
from collections import Counter
from typing import Dict, List, Any

from .data_loader import split_by_label
from .config import ROS_FEATURES


def rq10_predictive_modeling(samples: List[Dict]) -> Dict:
    """RQ10: 漏洞可预测性建模与特征重要性分析"""

    try:
        from sklearn.linear_model import LogisticRegression
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import StratifiedKFold, cross_val_score
        from sklearn.preprocessing import StandardScaler, LabelEncoder
        from sklearn.metrics import roc_auc_score, classification_report
        SKLEARN_AVAILABLE = True
    except ImportError:
        SKLEARN_AVAILABLE = False

    if not SKLEARN_AVAILABLE:
        return {
            "error": "scikit-learn not available",
            "findings": ["scikit-learn未安装，无法进行预测建模"],
        }

    # ========================================================================
    # 1. 特征工程
    # ========================================================================
    feature_names = []
    X_rows = []
    y = []

    # 复杂度指标
    complexity_metrics = ['loc', 'sloc', 'num_functions_called', 'max_nesting_depth',
                          'num_conditions', 'cyclomatic_complexity', 'num_pointers']

    # API特征
    api_features = list(ROS_FEATURES.keys())

    # 分类特征编码
    languages = sorted(set(s["_language"] for s in samples))
    components = sorted(set(s["_component"] for s in samples))
    ros_versions = sorted(set(s["_ros_version"] for s in samples))

    for s in samples:
        row = []

        # 复杂度指标 (7个)
        for m in complexity_metrics:
            row.append(s["_metrics"].get(m, 0))

        # API特征 (12个)
        for feat in api_features:
            row.append(1 if s["_features"].get(feat, False) else 0)

        # 语言 one-hot (n-1个)
        for lang in languages[1:]:
            row.append(1 if s["_language"] == lang else 0)

        # 组件 one-hot (n-1个)
        for comp in components[1:]:
            row.append(1 if s["_component"] == comp else 0)

        # ROS版本 one-hot (n-1个)
        for ver in ros_versions[1:]:
            row.append(1 if s["_ros_version"] == ver else 0)

        X_rows.append(row)
        y.append(s["_label"])

    # 构建特征名列表
    feature_names = (
        complexity_metrics +
        [f"api_{f}" for f in api_features] +
        [f"lang_{l}" for l in languages[1:]] +
        [f"comp_{c}" for c in components[1:]] +
        [f"rosver_{v}" for v in ros_versions[1:]]
    )

    X = np.array(X_rows, dtype=float)
    y = np.array(y, dtype=int)

    # ========================================================================
    # 2. 逻辑回归 - 全模型 (5折交叉验证)
    # ========================================================================
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    # 全模型
    lr_full = LogisticRegression(max_iter=1000, random_state=42, C=1.0)
    auc_full_scores = cross_val_score(lr_full, X_scaled, y, cv=cv, scoring='roc_auc')

    # 拟合全数据获取系数
    lr_full.fit(X_scaled, y)
    full_coefs = lr_full.coef_[0]

    # 特征重要性（按绝对值排序）
    feature_importance_lr = sorted(
        zip(feature_names, full_coefs.tolist()),
        key=lambda x: -abs(x[1])
    )

    # ========================================================================
    # 3. 嵌套模型比较（似然比检验）
    # ========================================================================
    # 模型1: 仅复杂度指标
    n_complexity = len(complexity_metrics)
    X_complexity = X_scaled[:, :n_complexity]
    lr_complexity = LogisticRegression(max_iter=1000, random_state=42, C=1.0)
    auc_complexity_scores = cross_val_score(lr_complexity, X_complexity, y, cv=cv, scoring='roc_auc')

    # 模型2: 复杂度 + API特征
    n_api_end = n_complexity + len(api_features)
    X_complexity_api = X_scaled[:, :n_api_end]
    lr_complexity_api = LogisticRegression(max_iter=1000, random_state=42, C=1.0)
    auc_complexity_api_scores = cross_val_score(lr_complexity_api, X_complexity_api, y, cv=cv, scoring='roc_auc')

    # 似然比检验（全数据拟合）
    lr_complexity.fit(X_complexity, y)
    lr_complexity_api.fit(X_complexity_api, y)

    def log_likelihood(model, X, y):
        probs = model.predict_proba(X)
        ll = 0
        for i in range(len(y)):
            p = probs[i][y[i]]
            p = max(p, 1e-10)
            ll += np.log(p)
        return ll

    ll_complexity = log_likelihood(lr_complexity, X_complexity, y)
    ll_complexity_api = log_likelihood(lr_complexity_api, X_complexity_api, y)
    ll_full = log_likelihood(lr_full, X_scaled, y)

    # LR test: complexity vs complexity+api
    lr_stat_1 = 2 * (ll_complexity_api - ll_complexity)
    df_1 = len(api_features)
    from scipy import stats as scipy_stats
    p_val_1 = 1 - scipy_stats.chi2.cdf(max(0, lr_stat_1), df_1)

    # LR test: complexity+api vs full
    lr_stat_2 = 2 * (ll_full - ll_complexity_api)
    df_2 = X_scaled.shape[1] - n_api_end
    p_val_2 = 1 - scipy_stats.chi2.cdf(max(0, lr_stat_2), df_2)

    nested_model_comparison = {
        "complexity_only": {
            "n_features": n_complexity,
            "auc_mean": float(np.mean(auc_complexity_scores)),
            "auc_std": float(np.std(auc_complexity_scores)),
            "auc_ci_lower": float(np.mean(auc_complexity_scores) - 1.96 * np.std(auc_complexity_scores)),
            "auc_ci_upper": float(np.mean(auc_complexity_scores) + 1.96 * np.std(auc_complexity_scores)),
        },
        "complexity_plus_api": {
            "n_features": n_api_end,
            "auc_mean": float(np.mean(auc_complexity_api_scores)),
            "auc_std": float(np.std(auc_complexity_api_scores)),
            "auc_ci_lower": float(np.mean(auc_complexity_api_scores) - 1.96 * np.std(auc_complexity_api_scores)),
            "auc_ci_upper": float(np.mean(auc_complexity_api_scores) + 1.96 * np.std(auc_complexity_api_scores)),
        },
        "full_model": {
            "n_features": X_scaled.shape[1],
            "auc_mean": float(np.mean(auc_full_scores)),
            "auc_std": float(np.std(auc_full_scores)),
            "auc_ci_lower": float(np.mean(auc_full_scores) - 1.96 * np.std(auc_full_scores)),
            "auc_ci_upper": float(np.mean(auc_full_scores) + 1.96 * np.std(auc_full_scores)),
        },
        "lr_test_api_addition": {
            "lr_statistic": float(lr_stat_1),
            "df": df_1,
            "p_value": float(p_val_1),
            "significant": p_val_1 < 0.05,
            "interpretation": "API特征显著提升模型" if p_val_1 < 0.05 else "API特征未显著提升模型",
        },
        "lr_test_categorical_addition": {
            "lr_statistic": float(lr_stat_2),
            "df": df_2,
            "p_value": float(p_val_2),
            "significant": p_val_2 < 0.05,
            "interpretation": "分类特征显著提升模型" if p_val_2 < 0.05 else "分类特征未显著提升模型",
        },
    }

    # ========================================================================
    # 4. 随机森林变量重要性
    # ========================================================================
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    auc_rf_scores = cross_val_score(rf, X_scaled, y, cv=cv, scoring='roc_auc')
    rf.fit(X_scaled, y)

    feature_importance_rf = sorted(
        zip(feature_names, rf.feature_importances_.tolist()),
        key=lambda x: -x[1]
    )

    # ========================================================================
    # 5. 汇总Top特征
    # ========================================================================
    top_features_lr = feature_importance_lr[:10]
    top_features_rf = feature_importance_rf[:10]

    # ========================================================================
    # Findings
    # ========================================================================
    findings = [
        f"全模型AUC: {np.mean(auc_full_scores):.3f} ± {np.std(auc_full_scores):.3f} (5折CV)",
        f"仅复杂度模型AUC: {np.mean(auc_complexity_scores):.3f}",
        f"复杂度+API模型AUC: {np.mean(auc_complexity_api_scores):.3f}",
        f"随机森林AUC: {np.mean(auc_rf_scores):.3f} ± {np.std(auc_rf_scores):.3f}",
        f"逻辑回归最重要特征: {top_features_lr[0][0]} (coef={top_features_lr[0][1]:.3f})",
        f"随机森林最重要特征: {top_features_rf[0][0]} (importance={top_features_rf[0][1]:.3f})",
    ]
    if p_val_1 < 0.05:
        findings.append("API特征对预测漏洞有显著贡献（似然比检验）")

    return {
        "full_model_auc": {
            "mean": float(np.mean(auc_full_scores)),
            "std": float(np.std(auc_full_scores)),
            "scores": auc_full_scores.tolist(),
        },
        "random_forest_auc": {
            "mean": float(np.mean(auc_rf_scores)),
            "std": float(np.std(auc_rf_scores)),
            "scores": auc_rf_scores.tolist(),
        },
        "nested_model_comparison": nested_model_comparison,
        "feature_importance_logistic": top_features_lr[:15],
        "feature_importance_random_forest": top_features_rf[:15],
        "feature_names": feature_names,
        "n_samples": len(samples),
        "n_features": len(feature_names),
        "findings": findings,
    }
