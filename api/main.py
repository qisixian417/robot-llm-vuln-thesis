"""FastAPI后端服务 - 简化版单Agent架构"""

import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

load_dotenv()

app = FastAPI(
    title="RoboGuard API",
    description="基于RAG增强的ROS函数级安全漏洞检测系统",
    version="1.0.0"
)

# 添加CORS支持
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_llm():
    """创建LLM实例"""
    return ChatOpenAI(
        model=os.getenv("MODEL_NAME", "qwen-plus"),
        openai_api_key=os.getenv("DASHSCOPE_API_KEY"),
        openai_api_base=os.getenv(
            "MODEL_BASE_URL",
            "https://dashscope.aliyuncs.com/compatible-mode/v1"
        ),
        temperature=0.1,
        max_tokens=4096
    )


class CodeRequest(BaseModel):
    """代码检测请求"""
    code: str
    language: Optional[str] = "C++"


class VulnerableLine(BaseModel):
    """漏洞行信息"""
    line_number: int
    code: str
    explanation: str


class VulnerabilityInfo(BaseModel):
    """漏洞信息"""
    has_vulnerability: bool
    vulnerability_type: Optional[str] = None
    reason: str
    confidence: float
    vulnerable_lines: List[VulnerableLine] = []
    retrieved_knowledge: List[Dict[str, Any]] = []


class DetectionResponse(BaseModel):
    """检测响应"""
    success: bool
    result: Optional[VulnerabilityInfo] = None
    error: Optional[str] = None


@app.get("/")
async def root():
    """API根路径"""
    return {
        "message": "RoboGuard API - 基于RAG增强的ROS函数级安全漏洞检测系统",
        "version": "1.0.0",
        "endpoints": {
            "detect": "/detect - POST - 检测代码漏洞",
            "health": "/health - GET - 健康检查",
            "stats": "/stats - GET - 系统统计"
        }
    }


@app.get("/health")
async def health_check():
    """健康检查"""
    from rag.retriever import RAGRetriever

    try:
        persist_dir = os.getenv("CHROMA_PERSIST_DIR", "./data/chroma_db")
        rag_retriever = RAGRetriever(persist_dir=persist_dir)
        doc_count = rag_retriever.count()

        return {
            "status": "healthy",
            "rag_ready": doc_count > 0,
            "rag_doc_count": doc_count,
            "model": os.getenv("MODEL_NAME", "qwen-plus")
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }


@app.get("/stats")
async def get_stats():
    """获取系统统计信息"""
    from rag.retriever import RAGRetriever

    try:
        persist_dir = os.getenv("CHROMA_PERSIST_DIR", "./data/chroma_db")
        rag_retriever = RAGRetriever(persist_dir=persist_dir)

        return {
            "rag_corpus_size": rag_retriever.count(),
            "model": os.getenv("MODEL_NAME", "qwen-plus"),
            "embedding_model": os.getenv("EMBEDDING_MODEL", "text-embedding-v2"),
            "supported_languages": ["C++", "Python"],
            "supported_cwe_types": [
                "CWE-119", "CWE-78", "CWE-401", "CWE-476",
                "CWE-362", "CWE-416", "CWE-190", "CWE-134"
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/detect", response_model=DetectionResponse)
async def detect_vulnerabilities(request: CodeRequest):
    """检测代码漏洞"""
    from agents import VulnDetectorAgent
    from rag.retriever import RAGRetriever

    try:
        # 初始化LLM
        llm = get_llm()

        # 初始化RAG检索器
        persist_dir = os.getenv("CHROMA_PERSIST_DIR", "./data/chroma_db")
        rag_retriever = RAGRetriever(persist_dir=persist_dir)

        if not rag_retriever.is_ready():
            raise HTTPException(
                status_code=500,
                detail=(
                    "向量数据库为空。请先执行 "
                    "`python3 scripts/build_chroma_db.py --reset` 构建知识库。"
                )
            )

        # 初始化检测Agent
        detector = VulnDetectorAgent(llm=llm, rag_retriever=rag_retriever)

        # 执行检测
        result = await detector.detect(request.code)

        return DetectionResponse(
            success=True,
            result=VulnerabilityInfo(**result)
        )

    except Exception as e:
        return DetectionResponse(
            success=False,
            error=str(e)
        )


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("API_HOST", "0.0.0.0")
    port = int(os.getenv("API_PORT", 8000))

    print(f"🚀 启动RoboGuard API服务...")
    print(f"📍 访问地址: http://{host}:{port}")
    print(f"📖 API文档: http://{host}:{port}/docs")

    uvicorn.run(app, host=host, port=port)
