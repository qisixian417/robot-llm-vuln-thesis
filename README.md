# RoboGuard — 面向机器人代码的漏洞检测与自动修复系统

> 硕士毕业论文项目
> 更新日期：2026-06-10

---

## 项目简介

本项目构建了一个**检测-修复一体化系统**，针对机器人代码（ROS core_middleware 生态）的函数级漏洞，实现自动检测和自动修复。

| 工作量 | 内容 | 核心技术 |
|---|---|---|
| **工作量1：漏洞检测** | 判断代码是否有漏洞、是什么类型 | KL-RAG + Multi-Agent + Docker沙箱 |
| **工作量2：漏洞修复** | 自动生成修复代码并验证有效 | ReAct + KL-RAG + Debate + LLM自检 |

---

## 核心创新

**Knowledge-Level RAG（KL-RAG）**：检索漏洞知识语义（root_cause / trigger_condition / fix_pattern），而非代码字面，使 CWE-401 召回率从 0% 提升至 55%。

**漏洞修复 ReAct 闭环**：生成修复代码 → Docker沙箱验证 → Debate评审反馈 → 多轮迭代，直到修复通过双重验证。

---

## 数据集

### 检测数据集（v1，旧，基线实验）
- 路径：`data/`
- 865条，38个机器人GitHub项目，单侧数据（无 fixed_code）

### 修复数据集（v2，新，当前使用）
- 路径：`data_v2/processed/`
- 训练集：478条（漏洞239 + 干净239），成对数据
- 测试集：277条（漏洞138 + 干净139），成对数据
- 每条都有 `vulnerable_code` + `fixed_code`（人工修复 ground truth）
- 来源：16个 ROS core_middleware 仓库，CVE路 + commit路双源

---

## 快速开始

### 环境配置

```bash
git clone https://github.com/qisixian417/robot-llm-vuln-thesis.git
cd robot-llm-vuln-thesis
pip install -r requirements.txt
```

创建 `.env` 文件：
```
DASHSCOPE_API_KEY=你的key
MODEL_NAME=qwen-plus
EMBEDDING_MODEL=text-embedding-v3
EMBEDDING_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
LLM_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
```

### 构建数据集（新电脑需要重新生成）

```bash
# 5步构建数据集
python scripts/build_dataset_v2/build_all.py

# 构建KL-RAG知识库
python scripts/build_knowledge_base.py \
  --input data_v2/processed/rag_corpus_v2.jsonl \
  --output data_v2/processed/rag_knowledge_v2.jsonl

# 构建向量数据库
python scripts/build_kl_chroma_db.py \
  --input data_v2/processed/rag_knowledge_v2.jsonl \
  --persist-dir data_v2/chroma_kl_db \
  --reset
```

### 运行漏洞检测实验

```bash
python scripts/evaluate.py \
  --config kl_rag_only \
  --test data_v2/processed/test_v2.jsonl
```

### 运行漏洞修复实验

```bash
# 需要先启动 Docker Desktop
python scripts/evaluate_repair.py \
  --limit 20 \
  --output experiments/repair/eval_repair_demo.json
```

### 运行实证研究

```bash
python scripts/empirical_study_v3.py
```

---

## 项目结构

```
agents/
  vuln_detector.py      漏洞检测 Agent
  router.py             CWE 路由 Agent
  verifier.py           沙箱验证 Agent（检测用）
  sandbox.py            Docker 沙箱执行器
  cwe_prompts.py        9种CWE检测Prompt
  repair_agent.py       漏洞修复核心 Agent（ReAct + 自检 + Debate）
  repair_prompts.py     7种CWE修复Prompt（CoT + Few-Shot）
  subagents.py          Voting + Debate
  plan_and_solve.py     Plan-and-Solve（高召回配置）
  ast_tool.py           AST代码特征提取

rag/
  knowledge_retriever.py  KL-RAG 知识级检索（核心）
  retriever.py            Dense 检索
  hybrid_retriever.py     BM25 + Dense 双路检索
  reranker.py             Cross-Encoder 重排
  corrective.py           CRAG 质量评估

pipeline/
  coordinator.py          检测系统流水线调度

scripts/
  evaluate.py             漏洞检测评估
  evaluate_repair.py      漏洞修复评估
  empirical_study_v3.py   实证研究（10个RQ）
  build_knowledge_base.py 构建KL-RAG知识库
  build_kl_chroma_db.py   构建向量数据库
  build_dataset_v2/       数据集重构5步流水线
  empirical_analysis/     10个RQ子模块

data/                     旧数据集（v1，保留备份）
data_v2/
  processed/              新数据集（v2，当前使用）
  chroma_kl_db/           KL-RAG向量数据库

experiments/
  repair/                 修复实验结果
  v3/                     实证研究结果（10个RQ）
  figures/                实验图表
```

---

## 实验结果

### 漏洞检测（旧数据集基线）

| 方法 | Precision | Recall | F1 |
|---|---|---|---|
| Cppcheck（传统工具）| 0.271 | 0.528 | 0.359 |
| Naive LLM | 0.318 | 0.556 | 0.404 |
| Code-Level RAG | 0.319 | 0.611 | 0.419 |
| **KL-RAG（最优）** | 0.314 | **0.750** | **0.443** |

### 漏洞检测（新数据集，20条小样本）

| 配置 | F1 | P | R |
|---|---|---|---|
| kl_rag_only | 0.471 | 0.667 | 0.364 |

### 漏洞修复（小样本测试）

| 指标 | 结果 |
|---|---|
| 可编译率 | 1.000 |
| ReAct 迭代 | 正常（Debate反馈驱动多轮改进）|
| 全量修复结果 | 待跑 |

---

## 技术栈

| 角色 | 配置 |
|---|---|
| LLM | qwen-plus / qwen-max（DashScope）|
| Embedding | text-embedding-v3（1024维）|
| Reranker | FlashRank ms-marco-MiniLM-L-12-v2 |
| 向量数据库 | Chroma |
| 沙箱 | Docker + ASan/TSan/UBSan |
| 静态分析 | Cppcheck 2.20 |
| Agent框架 | Python asyncio |

---

## 相关文档

- `导师汇报_最终版.md` — 完整项目汇报材料
- `项目组件全览.md` — 所有组件实验结果
- `项目实验流程清单.md` — 待做任务清单
- `VULNERABILITY_VS_BUG.md` — 漏洞vs Bug判断标准
