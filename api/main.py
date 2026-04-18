"""FastAPI后端服务"""

import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

load_dotenv()

app = FastAPI(title="RoboGuard API")


def get_llm():
    """创建千问LLM实例（DashScope OpenAI兼容接口）"""
    return ChatOpenAI(
        model=os.getenv("MODEL_NAME", "qwen-plus"),
        api_key=os.getenv("DASHSCOPE_API_KEY"),
        base_url=os.getenv(
            "LLM_BASE_URL",
            "https://dashscope.aliyuncs.com/compatible-mode/v1"
        ),
        temperature=0.1,
        max_tokens=4096
    )


class CodeRequest(BaseModel):
    code: str
    language: Optional[str] = "cpp"


class DetectionResponse(BaseModel):
    analysis: dict
    vulnerabilities: list
    fixes: list


@app.get("/")
async def root():
    return {"message": "RoboGuard API"}


@app.post("/detect", response_model=DetectionResponse)
async def detect_vulnerabilities(request: CodeRequest):
    """检测代码漏洞"""
    from agents import OrchestratorAgent, CodeAnalyzerAgent, VulnDetectorAgent, FixGeneratorAgent
    from rag.retriever import RAGRetriever

    llm = get_llm()
    persist_dir = os.getenv("CHROMA_PERSIST_DIR", "./data/chroma_db")
    rag_retriever = RAGRetriever(persist_dir=persist_dir)
    if not rag_retriever.is_ready():
        raise HTTPException(
            status_code=500,
            detail=(
                "Chroma 向量数据库为空。请先执行 "
                "`python3 scripts/build_chroma_db.py --reset` 构建知识库，"
                f"当前目录: {persist_dir}"
            ),
        )

    orchestrator = OrchestratorAgent(llm)
    orchestrator.register_agent("code_analyzer", CodeAnalyzerAgent(llm))
    orchestrator.register_agent("vuln_detector", VulnDetectorAgent(llm, rag_retriever))
    orchestrator.register_agent("fix_generator", FixGeneratorAgent(llm))

    result = await orchestrator.process(request.code, {})
    return DetectionResponse(
        analysis=result.get("analysis") or {},
        vulnerabilities=result.get("vulnerabilities") or [],
        fixes=result.get("fixes") or []
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.getenv("API_HOST", "0.0.0.0"), port=int(os.getenv("API_PORT", 8000)))
