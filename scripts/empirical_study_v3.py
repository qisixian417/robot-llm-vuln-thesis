# [实证研究主入口] 运行10个RQ分析（D-RQ1~D-RQ6 + C-RQ1~C-RQ2），生成报告和LaTeX表格，用于论文第6章
#!/usr/bin/env python3
"""
ROS安全漏洞实证研究 v3 - 主入口脚本
10个RQ，完整统计严谨性，可视化输出，LaTeX表格

Usage:
    python3 scripts/empirical_study_v3.py
    python3 scripts/empirical_study_v3.py --dataset data/dataset_final_v2.jsonl
    python3 scripts/empirical_study_v3.py --no-viz  # 跳过可视化
"""

import json
import argparse
import time
from pathlib import Path
from typing import Dict

# 添加项目根目录到路径
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.empirical_analysis.config import OUTPUT_DIR, FIGURES_DIR, DATASET_PATH
from scripts.empirical_analysis.data_loader import (
    load_jsonl, preprocess_samples, get_dataset_summary, convert_to_native
)
from scripts.empirical_analysis.rq01_taxonomy import rq1_vulnerability_taxonomy
from scripts.empirical_analysis.rq02_component import rq2_component_architecture
from scripts.empirical_analysis.rq03_complexity import rq3_code_complexity
from scripts.empirical_analysis.rq04_language import rq4_language_characteristics
from scripts.empirical_analysis.rq05_api_features import rq5_ros_feature_association
from scripts.empirical_analysis.rq06_code_patterns import rq6_code_patterns
from scripts.empirical_analysis.rq07_severity import rq7_severity_analysis
from scripts.empirical_analysis.rq08_repository import rq8_repository_analysis
from scripts.empirical_analysis.rq09_interaction import rq9_interaction_analysis
from scripts.empirical_analysis.rq10_predictive import rq10_predictive_modeling


def main():
    parser = argparse.ArgumentParser(description='ROS安全漏洞实证研究 v3')
    parser.add_argument('--dataset', type=str, default=None)
    parser.add_argument('--no-viz', action='store_true', help='跳过可视化生成')
    parser.add_argument('--rq', type=str, default=None, help='只运行指定RQ (如: 1,3,10)')
    args = parser.parse_args()

    # 选择数据集
    dataset_path = Path(args.dataset) if args.dataset else DATASET_PATH
    if not dataset_path.exists():
        print(f"错误: 数据集不存在: {dataset_path}")
        sys.exit(1)

    # 确定要运行的RQ
    if args.rq:
        run_rqs = set(int(x) for x in args.rq.split(','))
    else:
        run_rqs = set(range(1, 11))

    print('=' * 80)
    print('ROS安全漏洞实证研究 v3（增强版）')
    print('=' * 80)
    print(f'数据集: {dataset_path}')
    print(f'输出目录: {OUTPUT_DIR}')
    print(f'运行RQ: {sorted(run_rqs)}')
    print()

    # 加载和预处理数据
    print('加载数据集...')
    raw_samples = load_jsonl(dataset_path)
    samples = preprocess_samples(raw_samples)
    summary = get_dataset_summary(samples)
    print(f'  总样本: {summary["total"]} (漏洞: {summary["vulnerable"]}, 良性: {summary["benign"]})')
    print(f'  语言: {summary["languages"]}')
    print(f'  CWE类型: {summary["num_cwe_types"] if "num_cwe_types" in summary else len(summary.get("cwe_types", {}))}种')
    print(f'  仓库数: {summary["repos"]}')
    print()

    results = {"dataset_summary": summary}
    start_time = time.time()

    # ========================================================================
    # 运行各RQ
    # ========================================================================

    if 1 in run_rqs:
        print('RQ1: 漏洞类型分布与分类体系...')
        t0 = time.time()
        results['rq1'] = rq1_vulnerability_taxonomy(samples)
        r1 = results['rq1']
        print(f"  完成 ({time.time()-t0:.1f}s) - {r1.get('n_cwe_types', '?')}种CWE, "
              f"Shannon熵={r1.get('diversity', {}).get('shannon_entropy', 0):.3f}")

    if 2 in run_rqs:
        print('RQ2: ROS组件与架构根因分析...')
        t0 = time.time()
        results['rq2'] = rq2_component_architecture(samples)
        print(f"  完成 ({time.time()-t0:.1f}s)")

    if 3 in run_rqs:
        print('RQ3: 代码复杂度与漏洞相关性...')
        t0 = time.time()
        results['rq3'] = rq3_code_complexity(samples)
        print(f"  完成 ({time.time()-t0:.1f}s)")

    if 4 in run_rqs:
        print('RQ4: 语言特定漏洞特征...')
        t0 = time.time()
        results['rq4'] = rq4_language_characteristics(samples)
        print(f"  完成 ({time.time()-t0:.1f}s)")

    if 5 in run_rqs:
        print('RQ5: ROS API特征与漏洞关联...')
        t0 = time.time()
        results['rq5'] = rq5_ros_feature_association(samples)
        print(f"  完成 ({time.time()-t0:.1f}s)")

    if 6 in run_rqs:
        print('RQ6: 漏洞代码反模式与ROS架构缺陷...')
        t0 = time.time()
        results['rq6'] = rq6_code_patterns(samples)
        print(f"  完成 ({time.time()-t0:.1f}s)")

    if 7 in run_rqs:
        print('RQ7: 严重程度分析...')
        t0 = time.time()
        results['rq7'] = rq7_severity_analysis(samples)
        print(f"  完成 ({time.time()-t0:.1f}s)")

    if 8 in run_rqs:
        print('RQ8: 仓库级漏洞集中度分析...')
        t0 = time.time()
        results['rq8'] = rq8_repository_analysis(samples)
        print(f"  完成 ({time.time()-t0:.1f}s)")

    if 9 in run_rqs:
        print('RQ9: 交叉维度交互分析...')
        t0 = time.time()
        results['rq9'] = rq9_interaction_analysis(samples)
        print(f"  完成 ({time.time()-t0:.1f}s)")

    if 10 in run_rqs:
        print('RQ10: 漏洞可预测性建模...')
        t0 = time.time()
        results['rq10'] = rq10_predictive_modeling(samples)
        print(f"  完成 ({time.time()-t0:.1f}s)")

    total_time = time.time() - start_time
    print(f'\n所有RQ分析完成，总耗时: {total_time:.1f}s')

    # ========================================================================
    # 保存结果
    # ========================================================================
    print('\n保存结果...')

    # JSON结果
    json_path = OUTPUT_DIR / 'empirical_study_v3_results.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(convert_to_native(results), f, ensure_ascii=False, indent=2)
    print(f'  ✅ JSON结果: {json_path}')

    # LaTeX表格
    try:
        from scripts.empirical_analysis.latex_output import save_latex_tables
        tex_path = save_latex_tables(results)
        print(f'  ✅ LaTeX表格: {tex_path}')
    except Exception as e:
        print(f'  ⚠️ LaTeX表格生成失败: {e}')

    # Markdown报告
    md_path = OUTPUT_DIR / 'empirical_study_v3_report.md'
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(generate_report(results))
    print(f'  ✅ Markdown报告: {md_path}')

    # ========================================================================
    # 可视化
    # ========================================================================
    if not args.no_viz:
        print('\n生成可视化图表...')
        try:
            from scripts.empirical_analysis.visualization import generate_all_figures
            generate_all_figures(results, samples)
            print(f'  ✅ 图表目录: {FIGURES_DIR}')
        except Exception as e:
            print(f'  ⚠️ 可视化生成失败: {e}')
            import traceback
            traceback.print_exc()

    # ========================================================================
    # 打印关键发现摘要
    # ========================================================================
    print('\n' + '=' * 80)
    print('关键发现摘要')
    print('=' * 80)

    for rq_key in sorted(results.keys()):
        if rq_key.startswith('rq') and isinstance(results[rq_key], dict):
            findings = results[rq_key].get('findings', [])
            if findings:
                print(f'\n{rq_key.upper()}:')
                for finding in findings[:3]:
                    print(f'  • {finding}')

    print('\n' + '=' * 80)
    print('实证研究 v3 完成！')
    print('=' * 80)


def generate_report(results: Dict) -> str:
    """生成Markdown报告"""
    lines = [
        "# ROS安全漏洞实证研究报告 v3（增强版）",
        "",
        "## 摘要",
        "",
        f"本研究基于 {results.get('dataset_summary', {}).get('total', 0)} 个ROS代码样本"
        f"（{results.get('dataset_summary', {}).get('vulnerable', 0)} 个漏洞 + "
        f"{results.get('dataset_summary', {}).get('benign', 0)} 个良性），"
        "进行了10个研究问题（RQ）的深入实证分析。",
        "",
        "## 统计方法",
        "",
        "- 多重比较校正：Holm-Bonferroni（RQ内）、Benjamini-Hochberg FDR（探索性分析）",
        "- 效应量：Cliff's delta + Bootstrap 95% CI、Cohen's d、Vargha-Delaney A、Cramér's V、Odds Ratio",
        "- 假设检验：Mann-Whitney U、Fisher's exact、卡方检验、比例z检验",
        "- 预测建模：逻辑回归、随机森林、5折分层交叉验证",
        "",
    ]

    rq_titles = {
        'rq1': 'RQ1: 漏洞类型分布与分类体系',
        'rq2': 'RQ2: ROS组件与架构根因分析',
        'rq3': 'RQ3: 代码复杂度与漏洞相关性',
        'rq4': 'RQ4: 语言特定漏洞特征',
        'rq5': 'RQ5: ROS API特征与漏洞关联',
        'rq6': 'RQ6: 漏洞代码反模式与ROS架构缺陷',
        'rq7': 'RQ7: 严重程度分析',
        'rq8': 'RQ8: 仓库级漏洞集中度分析',
        'rq9': 'RQ9: 交叉维度交互分析',
        'rq10': 'RQ10: 漏洞可预测性建模',
    }

    for rq_key, title in rq_titles.items():
        if rq_key in results and isinstance(results[rq_key], dict):
            lines.extend([f"## {title}", ""])
            findings = results[rq_key].get('findings', [])
            for finding in findings:
                lines.append(f"- {finding}")
            lines.append("")

    # 威胁到有效性
    lines.extend([
        "## 威胁到有效性 (Threats to Validity)",
        "",
        "### 内部有效性",
        "- 代码片段为函数级片段，复杂度指标为近似计算（基于正则而非AST）",
        "- 部分样本的CWE标签由LLM辅助标注，可能存在噪声",
        "- 严重程度分配方法需进一步文档化",
        "",
        "### 外部有效性",
        "- 数据集限于38个仓库，可能无法泛化到所有ROS项目",
        "- C++样本占78%，Python相关发现的统计功效较低",
        "- 高严重程度样本稀少（CRITICAL仅5个），相关分析功效受限",
        "",
        "### 构建有效性",
        "- 漏洞密度为每样本计算，非每千行代码（KLOC）",
        "- ROS API特征检测基于正则表达式，可能存在假阳性/假阴性",
        "- 代码反模式检测为启发式方法，非精确的程序分析",
        "",
        "### 统计结论有效性",
        "- 全面应用多重比较校正",
        "- 效应量伴随显著性报告",
        "- Bootstrap CI提供对分布假设的鲁棒性",
        "",
    ])

    return "\n".join(lines)


if __name__ == '__main__':
    main()
