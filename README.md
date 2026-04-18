# RoboGuard - Multi-Agent机器人代码安全检测系统

## 项目概述
基于LangGraph的Multi-Agent系统，用于检测机器人代码中的安全漏洞。本项目是985硕士毕业论文的实验代码。

## 核心创新点
1. **Multi-Agent协同架构**：通过Orchestrator协调多个专业Agent，提升检测准确率
2. **机器人领域知识增强**：构建ROS专用漏洞知识库，结合RAG实现上下文感知检测

## 技术栈
- LangGraph/LangChain (Agent框架)
- Claude API / GPT-4 (大模型)
- ChromaDB (向量数据库)
- FastAPI (后端服务)
- Streamlit (前端界面)

## 项目结构
```
roboguard/
├── agents/          # Agent实现
├── rag/            # RAG系统
├── api/            # FastAPI后端
├── frontend/       # Streamlit前端
├── data/           # 知识库数据
├── experiments/    # 实验评估
└── scripts/        # 工具脚本
```

## 快速开始
```bash
# 1. 安装依赖
python3 -m pip install -r requirements.txt

# 2. 配置API Key
cp .env.example .env
# 编辑.env文件，填入你的API Key

# 3. 构建 Chroma 向量数据库
python3 scripts/build_chroma_db.py --reset

# 4. 启动后端服务
python api/main.py

# 5. 启动前端界面
streamlit run frontend/app.py
```

## 环境要求
- Python 3.10+
- Claude API Key 或 OpenAI API Key
