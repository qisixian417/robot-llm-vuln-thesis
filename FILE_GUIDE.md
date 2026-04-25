# RoboGuard 项目文件说明

本文档说明项目中每个文件的用途，帮助理解项目结构。

---

## 📁 核心系统文件

### Web界面
- **`app.py`** - Streamlit Web界面，提供可视化的漏洞检测交互界面
- **`start_ui.sh`** - Web界面启动脚本，一键启动Streamlit服务

### API服务
- **`api/main.py`** - FastAPI后端服务，提供RESTful API接口

### 检测引擎
- **`agents/vuln_detector.py`** - 核心漏洞检测Agent，基于RAG增强的LLM检测
- **`agents/__init__.py`** - agents模块初始化文件

### RAG系统
- **`rag/retriever.py`** - RAG检索器，从ChromaDB检索相关历史漏洞案例
- **`rag/__init__.py`** - rag模块初始化文件

### 配置文件
- **`configs/agent.yaml`** - Agent和RAG系统配置（模型、CWE类型、检索参数等）
- **`requirements.txt`** - Python依赖包列表
- **`.env`** - API密钥配置（需自行创建，参考.env.example）

---

## 📊 数据集文件（data/目录）

### 最终数据集（v2版本，当前使用）⭐
- **`dataset_final_v2.jsonl`** - 完整合并数据集（865个样本）
- **`train_v2.jsonl`** - 训练集（645个样本）
- **`test_v2.jsonl`** - 测试集（220个样本）
- **`rag_corpus_v2.jsonl`** - RAG知识库语料（378个漏洞案例，仅来自训练集）

### 中间数据文件
- **`dataset_labeled.jsonl`** - 补标后的数据集（781个样本，所有样本都有CWE标签）
- **`github_expanded_samples.jsonl`** - 从GitHub新仓库扩充的样本（94个）

### 向量数据库
- **`chroma_db/`** - ChromaDB向量数据库目录（约11MB）

---

## 🧪 实验结果文件（experiments/目录）

### 实证研究结果（最新）⭐
- **`empirical_study_v2_results.json`** - 7个研究问题的完整结构化结果
- **`empirical_study_v2_report.md`** - 实证研究Markdown报告
- **`empirical_study_v2_tables.tex`** - LaTeX表格（可直接插入论文）

### 模式分析结果
- **`pattern_analysis.json`** - 8种CWE类型的ROS特定模式分析（结构化数据）
- **`pattern_analysis.md`** - 模式分析Markdown报告

### 消融实验结果
- **`ablation_clean_20260425_022506.json`** - RAG vs No-RAG消融实验结果（20样本）

---

## 🔧 脚本文件（scripts/目录）

### 数据处理脚本
- **`label_unlabeled_samples.py`** - 用LLM自动补标180个无CWE标签的样本
- **`expand_dataset_github.py`** - 从13个新GitHub仓库扩充数据集
- **`merge_and_split_dataset.py`** - 合并数据集、添加元数据、分层划分train/test
- **`build_chroma_db.py`** - 构建ChromaDB向量数据库（从RAG语料库）

### 分析与评估脚本
- **`empirical_study_v2.py`** - 深入版实证研究（7个RQ，700+行）
- **`analyze_patterns.py`** - 分析8种CWE类型的ROS特定模式
- **`run_ablation_experiments.py`** - 运行消融实验（RAG vs No-RAG）
- **`test_agent.py`** - 测试检测系统（可用于全量评估）

---

## 📖 文档文件

### 核心文档
- **`README.md`** - 项目总览、快速开始、使用说明
- **`docs/LITERATURE_SURVEY.md`** - 文献调研报告

### 使用指南
- **`WEB_UI_GUIDE.md`** - Web界面使用指南
- **`MANUAL_TEST_GUIDE.md`** - 手动测试指南
- **`VULNERABILITY_VS_BUG.md`** - 漏洞vs Bug判断标准

---

## 🎯 使用流程

### 1. 首次启动
```bash
# 安装依赖
pip install -r requirements.txt

# 配置API密钥
cp .env.example .env
# 编辑.env，填写DASHSCOPE_API_KEY

# 构建向量数据库
python3 scripts/build_chroma_db.py --reset --corpus data/rag_corpus_v2.jsonl

# 启动Web界面
./start_ui.sh
```

### 2. 运行实证研究
```bash
python3 scripts/empirical_study_v2.py --dataset data/dataset_final_v2.jsonl
```

### 3. 运行消融实验
```bash
python3 scripts/run_ablation_experiments.py
```

### 4. 测试检测系统
```bash
python3 scripts/test_agent.py
```

---

## ⚠️ 重要提醒

1. **数据集版本**：当前使用v2版本（dataset_final_v2.jsonl等），不要使用旧的v1版本
2. **RAG语料库**：必须只来自训练集，避免数据泄漏
3. **API密钥**：需要配置DASHSCOPE_API_KEY才能运行检测系统
4. **向量数据库**：首次使用前必须运行build_chroma_db.py构建

---

## 📝 论文相关

- **数据集**：865个样本（509漏洞 + 356正常）
- **实证研究**：7个研究问题（RQ1-RQ7）
- **检测效果**：RAG+LLM F1=0.71 vs 静态工具F1=0.0
- **关键发现**：详见experiments/empirical_study_v2_report.md

---

最后更新：2026-04-25
