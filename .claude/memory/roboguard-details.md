# RoboGuard 项目详细信息

## 项目定位（2024-04-24更新）
- **检测粒度**: 函数级（不是项目级或行级）
- **目标**: 985硕士毕业论文，能毕业即可
- **创新点**: RAG增强的ROS函数级安全检测

## 架构简化说明
原计划使用Multi-Agent架构（Orchestrator + CodeAnalyzer + VulnDetector + FixGenerator），但考虑到：
1. 函数级检测不需要复杂的代码分析
2. 实现难度要适中（计算机基础不强）
3. 论文重点在RAG增强，不在Multi-Agent

**已简化为单Agent架构**：
- 只保留VulnDetectorAgent
- 删除了Orchestrator, CodeAnalyzer, FixGenerator

## VulnDetectorAgent实现
```python
class VulnDetectorAgent:
    def __init__(self, llm, rag_retriever=None)
    async def detect(code, analysis) -> List[Dict]:
        # 1. 使用RAG检索相关漏洞案例
        # 2. 结合历史案例检测当前函数
        # 3. 返回漏洞列表
```

## 数据集详情（2024-04-24更新）

### 文件说明
- `dataset_full.jsonl.backup`: 原始数据集（809样本）
- `dataset_filtered.jsonl`: 过滤后的函数级数据集（400样本）
- `train.jsonl`: 训练集（321样本）
- `test.jsonl`: 测试集（79样本）
- `rag_corpus_full.jsonl`: RAG语料库（595样本）

### 数据集统计
**过滤后数据集（400样本）**:
- 有漏洞: 134 (33.5%)
- 无漏洞: 266 (66.5%)
- C++: 273 (68.3%)
- Python: 127 (31.8%)

**训练集（321样本）**:
- 有漏洞: 108 (33.6%)
- 无漏洞: 213 (66.4%)

**测试集（79样本）**:
- 有漏洞: 26 (32.9%)
- 无漏洞: 53 (67.1%)

### 数据泄漏问题
⚠️ **重要**: 所有134个有漏洞样本都在RAG语料库中
- 为了评估需要，从RAG中抽取20%到测试集
- 测试集有轻微数据泄漏风险
- 论文中需要说明这个限制

### 过滤标准
删除了409个低质量样本：
- 单行代码（115个）
- 代码片段<3行（82个）
- 其他质量不足（212个）

保留标准：
- 至少3行代码
- 包含完整函数定义或代码块
- C++: 有函数定义或至少5行逻辑代码
- Python: 有def关键字或至少5行代码

## 配置文件 (configs/agent.yaml)
```yaml
agent:
  model: qwen-plus
  base_url: https://dashscope.aliyuncs.com/compatible-mode/v1
  temperature: 0.1
  max_tokens: 4096

rag:
  persist_dir: ./data/chroma_db
  embedding_model: text-embedding-v2
  top_k: 3

detection:
  enable_rag: true
  enable_verification: true
```

## 关键脚本
- build_chroma_db.py: 构建向量数据库
- test_agent.py: 测试Agent系统
- evaluate_*.py: 各种评估脚本
- gen_dataset.py: 生成数据集
- crawl_github_dataset.py: 爬取GitHub数据

## 实验数据
experiments/目录包含多个评估结果JSON：
- static_tools_*.json: 静态工具评估
- qwen_*_rag_*.json: 千问模型+RAG评估
- fast_baselines_result.json: 基线对比

## 快速启动
```bash
# 构建向量数据库
python3 scripts/build_chroma_db.py --reset

# 启动后端
python api/main.py

# 启动前端（尚未实现）
streamlit run frontend/app.py
```

## 环境要求
- Python 3.10+
- API Keys: Claude/OpenAI/DashScope

## 论文建议
1. **定位**: ROS函数级安全检测（不是项目级或行级）
2. **重点漏洞**: 3-5种（命令注入、缓冲区溢出、内存泄漏、并发问题等）
3. **创新点**: RAG增强的机器人领域知识
4. **数据集规模**: 400个函数级样本（够毕业用）
5. **评估指标**: 准确率、召回率、F1-score
6. **需要说明的限制**: 测试集与RAG有重叠（数据泄漏）
