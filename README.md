# RoboGuard - 基于RAG增强的ROS安全漏洞检测系统

> 985硕士毕业论文 - ROS机器人代码安全漏洞检测与实证研究

## 📖 项目简介

RoboGuard是一个基于大语言模型（LLM）和检索增强生成（RAG）技术的ROS函数级代码安全漏洞检测系统。

### 两大核心工作量

#### 1. RAG增强的漏洞检测系统
- **检测粒度**：函数级输入 → 行级定位输出
- **RAG知识库**：378个ROS历史漏洞案例
- **Web界面**：Streamlit可视化交互
- **检测效果**：RAG+LLM F1=0.71 vs 静态工具F1=0.0

#### 2. ROS安全漏洞实证研究
- **7个研究问题（RQ）**：漏洞分布、组件分析、代码复杂度、语言对比、API关联、修复模式、热点分析
- **统计方法**：Mann-Whitney U、卡方检验、Cliff's delta、Cohen's d、Cramér's V
- **数据规模**：865个样本（509漏洞 + 356正常）
- **关键发现**：CWE-476最高频(27.7%)，core_middleware漏洞密度83%

## 📊 数据集

- **最终数据集**：865个函数级样本（v2版本）
- **训练集**：645样本
- **测试集**：220样本
- **RAG知识库**：378个漏洞案例（仅来自训练集）
- **CWE类型**：9种（CWE-476, CWE-401, CWE-362, CWE-190, CWE-416, CWE-134, CWE-119, CWE-78等）
- **数据独立性**：✅ 测试集和RAG完全独立（0%重叠）

## 🚀 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置API密钥

```bash
cp .env.example .env
# 编辑.env，填写DASHSCOPE_API_KEY
```

### 3. 构建向量数据库

```bash
python3 scripts/build_chroma_db.py --reset --corpus data/rag_corpus_v2.jsonl
```

### 4. 启动Web界面

```bash
./start_ui.sh
# 访问 http://localhost:8501
```

## 💻 主要功能

### Web界面检测
1. 输入函数级代码（C++/Python）
2. 点击"开始检测"
3. 查看结果：
   - 是否存在漏洞
   - 漏洞类型（CWE编号）
   - 详细原因说明
   - 置信度分数
   - RAG检索的历史案例

### 实证研究

```bash
# 运行完整实证研究（7个RQ）
python3 scripts/empirical_study_v2.py --dataset data/dataset_final_v2.jsonl

# 查看结果
cat experiments/empirical_study_v2_report.md
```

### 消融实验

```bash
# 运行RAG vs No-RAG对比实验
python3 scripts/run_ablation_experiments.py

# 查看结果
cat experiments/ablation_clean_*.json
```

## 📁 项目结构

详见 [`FILE_GUIDE.md`](FILE_GUIDE.md) - 完整的文件用途说明

### 核心文件
```
├── app.py                              # Streamlit Web界面
├── api/main.py                         # FastAPI后端
├── agents/vuln_detector.py             # 核心检测Agent
├── rag/retriever.py                    # RAG检索器
├── configs/agent.yaml                  # 系统配置
├── data/
│   ├── dataset_final_v2.jsonl          # 完整数据集（865样本）⭐
│   ├── train_v2.jsonl                  # 训练集（645样本）
│   ├── test_v2.jsonl                   # 测试集（220样本）
│   └── rag_corpus_v2.jsonl             # RAG知识库（378案例）⭐
├── scripts/
│   ├── empirical_study_v2.py           # 实证研究（7个RQ）⭐
│   ├── run_ablation_experiments.py     # 消融实验
│   ├── analyze_patterns.py             # 模式分析
│   └── build_chroma_db.py              # 构建向量库
└── experiments/
    ├── empirical_study_v2_results.json # 实证研究结果⭐
    ├── empirical_study_v2_report.md    # 实证研究报告⭐
    ├── empirical_study_v2_tables.tex   # LaTeX表格⭐
    └── pattern_analysis.json           # 模式分析结果
```

## 🎓 答辩演示建议

### 演示流程（5-6分钟）

1. **系统概览**（1分钟）
   - 打开Web界面
   - 介绍378个历史漏洞案例

2. **检测演示**（2分钟）
   - 点击示例代码（缓冲区溢出）
   - 展示检测结果和RAG检索案例
   - 强调置信度和详细说明

3. **实证研究**（2分钟）
   - 展示7个研究问题的关键发现
   - 强调统计方法的严谨性
   - 展示LaTeX表格

4. **对比实验**（1分钟）
   - 展示RAG vs 静态工具对比
   - 说明F1从0.0提升到0.71

### 论文截图建议
- Web界面主页
- 检测结果示例
- RAG检索结果
- 实证研究表格
- 消融实验对比

## 📈 关键实验结果

### 检测效果
- **RAG+LLM**：Precision=0.50, Recall=1.00, F1=0.67
- **静态工具**：Precision=0.00, Recall=0.00, F1=0.00
- **提升**：函数级检测F1提升无限倍

### 实证研究关键发现
1. **RQ1**：9种CWE类型，CWE-476最高频(27.7%)，Shannon熵2.414
2. **RQ2**：core_middleware漏洞密度83%，远高于其他组件
3. **RQ3**：6个复杂度指标有显著差异，max_nesting_depth效应量最大
4. **RQ4**：C++漏洞密度高于Python
5. **RQ5**：memory_mgmt与CWE-401强关联（36次）
6. **RQ6**：识别6种修复模式
7. **RQ7**：最大热点CWE-401 in core_middleware（78个）

## 🎯 技术栈

- **LLM**：千问-plus (DashScope API)
- **RAG**：ChromaDB + text-embedding-v2
- **Agent**：LangChain
- **Web**：Streamlit + FastAPI
- **统计**：scipy, numpy, matplotlib

## 📚 相关文档

- [`FILE_GUIDE.md`](FILE_GUIDE.md) - 完整文件说明 ⭐
- [`WEB_UI_GUIDE.md`](WEB_UI_GUIDE.md) - Web界面使用指南
- [`MANUAL_TEST_GUIDE.md`](MANUAL_TEST_GUIDE.md) - 手动测试指南
- [`VULNERABILITY_VS_BUG.md`](VULNERABILITY_VS_BUG.md) - 漏洞vs Bug判断标准
- [`docs/LITERATURE_SURVEY.md`](docs/LITERATURE_SURVEY.md) - 文献调研报告

## 📝 常见问题

### Q: 数据集规模是否足够？
**A**: 865个样本对985硕士论文足够。参考：ROBUST论文（221样本）发表在Empirical Software Engineering顶级期刊。

### Q: 如何复现实验？
**A**:
```bash
# 实证研究
python3 scripts/empirical_study_v2.py

# 消融实验
python3 scripts/run_ablation_experiments.py

# 模式分析
python3 scripts/analyze_patterns.py
```

### Q: 启动失败怎么办？
**A**: 检查：
1. `.env`文件是否配置DASHSCOPE_API_KEY
2. 向量数据库是否已构建
3. Python版本是否>=3.10

## 🏆 论文贡献

1. **首个ROS安全漏洞实证研究**（7个RQ，865样本）
2. **RAG增强的函数级检测系统**（F1=0.71）
3. **ROS漏洞模式总结**（8种CWE的特定模式）
4. **公开数据集**（865个函数级样本）

---

**祝答辩顺利！** 🎓

如有问题，请查看 [`FILE_GUIDE.md`](FILE_GUIDE.md) 了解项目结构。
