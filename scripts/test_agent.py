"""测试Agent系统"""

import asyncio
import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from agents import OrchestratorAgent, CodeAnalyzerAgent, VulnDetectorAgent, FixGeneratorAgent

load_dotenv()


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


async def test_agent_system():
    """测试Agent系统"""
    llm = get_llm()

    # 创建Orchestrator
    orchestrator = OrchestratorAgent(llm)

    # 注册子Agent
    orchestrator.register_agent("code_analyzer", CodeAnalyzerAgent(llm))
    orchestrator.register_agent("vuln_detector", VulnDetectorAgent(llm))
    orchestrator.register_agent("fix_generator", FixGeneratorAgent(llm))

    # 测试代码
    test_code = """
    void process_data(char* input) {
        char buffer[10];
        strcpy(buffer, input);  // 潜在缓冲区溢出
    }
    """

    result = await orchestrator.process(test_code, {})
    print("检测结果：", result)


if __name__ == "__main__":
    asyncio.run(test_agent_system())
