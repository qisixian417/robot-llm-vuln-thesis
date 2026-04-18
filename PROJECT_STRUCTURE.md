# RoboGuard 项目结构

## 📁 目录结构

```
robot-llm-vuln-thesis/
├── agents/                    # Multi-Agent系统核心
│   ├── __init__.py           # Agent模块导出
│   ├── orchestrator.py       # 协调Agent（调度中心）
│   ├── code_analyzer.py      # 代码分析Agent
│   ├── vuln_detector.py      # 漏洞检测Agent
│   └── fix_generator.py      # 修复建议Agent
│
├── rag/                      # RAG检索系统
│   ├── __init__.py
│   └── retriever.py          # 向量检索器
│
├── api/                      # FastAPI后端服务
│   └── main.py               # API入口
│
├── frontend/                 # Streamlit前端
│   └── app.py                # Web界面
│
├── scripts/                  # 工具脚本
│   ├── build_rag_index.py    # 构建知识库
│   └── test_agent.py         # 测试Agent系统
│
├── configs/                  # 配置文件
│   └── agent.yaml            # Agent配置
│
├── data/                     # 数据目录
│   └── chroma_db/            # 向量数据库（运行后生成）
│
├── experiments/              # 实验结果
│
├── .env.example              # 环境变量模板
├── .gitignore
├── requirements.txt          # Python依赖
└── README.md                 # 项目说明
```

## 🎯 核心模块说明

### 1. Multi-Agent系统 (agents/)

**Orchestrator Agent** - 协调中心
- 负责任务分解和Agent调度
- 管理工作流：分析 → 检测 → 修复

**Code Analyzer Agent** - 代码分析
- 分析代码结构和语义
- 识别代码类型（ROS节点/驱动等）
- 提取关键API调用

**Vuln Detector Agent** - 漏洞检测
- 结合RAG检索相关漏洞案例
- 检测常见安全问题
- 关注ROS特定漏洞

**Fix Generator Agent** - 修复建议
- 生成具体修复代码
- 解释修复原理

### 2. RAG系统 (rag/)

- 使用ChromaDB向量数据库
- 存储机器人领域漏洞案例
- 支持语义检索

### 3. Web服务 (api/ & frontend/)

- FastAPI提供REST API
- Streamlit提供用户界面
- 支持代码上传和实时检测

## 🚀 下一步工作

1. 安装依赖：`pip install -r requirements.txt`
2. 配置API Key：复制`.env.example`为`.env`并填入密钥
3. 测试Agent：`python scripts/test_agent.py`
4. 构建知识库：收集漏洞案例并运行`build_rag_index.py`
5. 启动服务：运行API和前端

## 📝 简历项目描述

**项目名称：** RoboGuard - 基于Multi-Agent的机器人代码安全检测系统

**技术栈：** LangChain, Claude API, ChromaDB, FastAPI, Streamlit

**创新点：**
1. Multi-Agent协同架构
2. 机器人领域知识增强RAG
