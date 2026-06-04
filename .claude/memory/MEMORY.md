# 项目记忆

## 毕业设计项目：RoboGuard
- **路径**: `/Users/yuan/Desktop/robot-llm-vuln-thesis`
- **类型**: 985硕士毕业论文实验代码
- **主题**: ROS函数级代码安全检测系统（基于RAG增强）
- **检测粒度**: 函数级（不是项目级或行级）

## 核心架构（已简化）
1. **漏洞检测模块** (agents/)
   - VulnDetectorAgent: 函数级漏洞检测，结合RAG检索历史漏洞案例
   - 已删除: Orchestrator, CodeAnalyzer, FixGenerator（不需要复杂Multi-Agent）

2. **RAG系统** (rag/)
   - ChromaDB向量数据库
   - 存储ROS历史漏洞案例（595个样本）
   - 语义检索支持

3. **Web服务**
   - FastAPI后端 (api/main.py) - 已重构为单Agent架构
   - Streamlit前端 (app.py) - Web界面已实现

## 数据集信息（重要！）（2024-04-24最终更新）
- **原始数据**: data/dataset_full.jsonl.backup (809样本)
- **清理后数据集**: data/dataset_cleaned.jsonl (781样本) ⭐
- **训练集**: data/train_cleaned.jsonl (582样本，39.2%有漏洞) ⭐
- **测试集**: data/test_cleaned.jsonl (199样本，40.2%有漏洞) ⭐
- **RAG语料库**: data/rag_corpus_cleaned.jsonl (228个漏洞案例) ⭐

### 数据集清理情况（2024-04-24完成）
- 删除28个Bug样本（crash during shutdown等非安全问题）
- 补充25个缺失的CWE标签（use-after-free→CWE-416, null pointer→CWE-476等）
- 清理后：781个样本，308个有漏洞（39.4%）
- CWE类型：8种（CWE-362, CWE-401, CWE-190, CWE-476, CWE-134, CWE-416, CWE-78, CWE-119）

### 数据集划分策略（已修复数据泄漏）
- 训练集：582个样本（228个有漏洞）
- 测试集：199个样本（80个有漏洞）
- RAG知识库：只包含训练集中的228个漏洞样本
- ✅ 测试集和RAG完全独立（0%重叠，之前是75.3%）
- 划分方法：分层抽样（按CWE类型）

### 数据质量
- 删除标准：crash during shutdown、crash in test等非安全Bug
- 补充标准：use-after-free→CWE-416, null pointer→CWE-476等
- 所有RAG样本都有明确的CWE标签
- 确保训练集和测试集完全独立

### ⚠️ 已删除的旧文件（不要再使用）
- data/dataset_final.jsonl (已删除)
- data/train_final.jsonl (已删除)
- data/test_final.jsonl (已删除)
- data/rag_corpus_full.jsonl (已删除，有数据泄漏)

## 技术栈
- Agent框架: LangGraph/LangChain
- LLM: Claude API / GPT-4 / 千问(qwen-plus via DashScope)
- 向量DB: ChromaDB (text-embedding-v2)
- Web: FastAPI + Streamlit
- 代码分析: tree-sitter, pygments

## 关键配置
- configs/agent.yaml: Agent和RAG配置
- .env: API密钥配置
- requirements.txt: Python依赖

## 目录结构
- agents/: VulnDetectorAgent（已简化）
- rag/: 检索器
- api/: FastAPI服务
- scripts/: 工具脚本（构建索引、评估等）
- data/: 数据集和chroma_db
- experiments/: 实验结果JSON文件

## 工作流程（简化）
输入函数代码 → RAG检索相关漏洞案例 → VulnDetector检测 → 输出漏洞报告

## 论文定位
- 函数级ROS安全检测（不是项目级或行级）
- 重点检测8种常见漏洞（竞态条件、内存泄漏、命令注入、整数溢出、空指针、Use After Free等）
- 创新点：RAG增强的机器人领域知识
- 数据集规模：781个函数级样本（985硕士论文足够）
- ✅ 数据集已清理，删除了Bug样本，只保留真正的漏洞

## 实验结果（2024-04-24）

### 系统输出格式
已实现5个关键输出：
1. 是否存在漏洞 (has_vulnerability)
2. 漏洞类型 (vulnerability_type: CWE-XXX)
3. 漏洞原因说明 (reason)
4. 置信度 (confidence: 0.0-1.0)
5. 检索到的RAG知识片段 (retrieved_knowledge)

### 对比实验：静态工具 vs RAG+LLM

**测试集**: 20个样本（3个有漏洞，17个无漏洞）

**静态工具（Cppcheck + Semgrep）**:
- 召回率: 0% (漏报所有3个漏洞)
- F1分数: 0.0000
- 问题：基于规则，无法检测复杂的函数级漏洞

**RAG+LLM（千问+595案例）**:
- 召回率: 100% (检测到所有3个漏洞)
- F1分数: 0.6667
- 精确率: 50% (3个误报)

**关键发现**:
- 静态工具更适合**行级检测**（单行危险函数）
- RAG+LLM更适合**函数级检测**（需要理解整个函数逻辑）
- F1分数提升: 从0.0000到0.6667（无限倍提升）

### 成功案例
- CWE-362 (Race Condition): 置信度0.92
- CWE-401 (Memory Leak): 置信度0.95
- CWE-78 (Command Injection): 置信度1.0

## Web界面（2024-04-24）

已实现Streamlit Web UI：
- **访问地址**: http://localhost:8501
- **启动命令**: `./start_ui.sh` 或 `streamlit run app.py`

**功能特性**：
1. 代码输入框（支持C++/Python）
2. 一键检测按钮
3. 结构化结果展示（5个关键字段）
4. RAG检索结果可视化
5. 4个预设示例代码
6. 响应式布局，颜色编码

**适用场景**：
- 毕业答辩演示
- 论文截图
- 功能测试
- 现场演示

### 手动测试
- 测试数据集位置: `data/test_cleaned.jsonl`
- 查看测试样本脚本: `view_test_samples.py`
- 手动测试指南: `MANUAL_TEST_GUIDE.md`
- Web界面已验证可启动并正常使用

## 代码重构状态（2024-04-24）
- 已完成从旧Multi-Agent架构到单Agent架构的重构
- 当前只保留 `VulnDetectorAgent`
- 已重构 `api/main.py`，改为单Agent FastAPI后端
- 已重构 `scripts/test_agent.py`，可直接测试当前系统
- 已删除无用脚本：`build_rag_index.py`、`gen_dataset.py`、`crawl_github_dataset.py`
- 已更新 `README.md`，内容与当前项目实际保持一致

## 当前建议使用的关键文件（2024-04-24更新）
- Web启动：`start_ui.sh`
- Web界面：`app.py`
- API后端：`api/main.py`
- 核心检测：`agents/vuln_detector.py`
- RAG检索：`rag/retriever.py`
- 向量库构建：`scripts/build_chroma_db.py`
- **清理后数据集**：`data/dataset_cleaned.jsonl` ⭐
- **训练集**：`data/train_cleaned.jsonl` ⭐
- **测试集**：`data/test_cleaned.jsonl` ⭐
- **RAG语料库**：`data/rag_corpus_cleaned.jsonl` ⭐

⚠️ 不要再使用旧文件：
- data/dataset_final.jsonl (已过时)
- data/train_final.jsonl (已过时)
- data/test_final.jsonl (已过时)
- data/rag_corpus_full.jsonl (已过时，有数据泄漏)

## 项目启动方式（当前正确方式）
1. `pip install -r requirements.txt`
2. `cp .env.example .env` 并填写 `DASHSCOPE_API_KEY`
3. `python3 scripts/build_chroma_db.py --reset`
4. `./start_ui.sh`
5. 浏览器访问 `http://localhost:8501`

详细使用说明见: WEB_UI_GUIDE.md
对比实验分析见: ANALYSIS_STATIC_VS_RAG.md
数据清理报告见: DATASET_CLEANING_REPORT.md
最终总结见: FINAL_SUMMARY.md
项目状态见: PROJECT_STATUS.md
清理报告见: CLEANUP_REPORT.md
手动测试指南见: MANUAL_TEST_GUIDE.md
漏洞vs Bug判断标准见: VULNERABILITY_VS_BUG.md
代码重构总结见: REFACTORING_SUMMARY.md
详细信息见: roboguard-details.md

## 本次对话的重要内容总结（2024-04-24）
- 完成了数据集清理：删除28个Bug样本，补充25个CWE标签
- 完成了RAG重建：只使用训练集中的228个漏洞案例，消除数据泄漏
- 完成了文件整理：删除11个旧数据文件和2个过时文档
- 更新了README和所有相关文档
- 解释了Bug vs 漏洞的区别：关键是CIA三元组和可利用性
- 解释了RAG vs 测试集的关系：RAG是知识库，测试集是评估集，必须完全独立
- 解释了数据集的作用：即使不训练模型，也用于评估、对比实验和构建RAG知识库
- 解释了代码逻辑中如何判断Bug vs 漏洞：基于关键词匹配和上下文规则
- 创建了手动测试指南，说明如何在UI中测试系统
- 当前项目状态：✅ 数据集已清理，系统就绪，可以开始重新运行实验
