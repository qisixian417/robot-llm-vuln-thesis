"""测试RoboGuard漏洞检测系统（简化版）"""

import asyncio
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents import VulnDetectorAgent
from rag.retriever import RAGRetriever

load_dotenv()


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


async def test_detection_system():
    """测试漏洞检测系统"""
    print("=" * 60)
    print("RoboGuard 漏洞检测系统测试")
    print("=" * 60)

    # 初始化LLM
    llm = get_llm()

    # 初始化RAG检索器
    rag_retriever = RAGRetriever(persist_dir="./data/chroma_db")
    if not rag_retriever.is_ready():
        print("❌ 向量数据库为空，请先运行：")
        print("   python3 scripts/build_chroma_db.py --reset")
        return

    print(f"✅ RAG知识库已加载：{rag_retriever.count()} 个案例")

    # 初始化检测器
    detector = VulnDetectorAgent(llm=llm, rag_retriever=rag_retriever)

    # 测试代码
    test_cases = [
        {
            "name": "缓冲区溢出",
            "code": """
void process_data(char* input) {
    char buffer[10];
    strcpy(buffer, input);  // 潜在缓冲区溢出
}
"""
        },
        {
            "name": "命令注入",
            "code": """
def execute_command(user_input):
    import os
    cmd = "ls " + user_input
    os.system(cmd)  # 潜在命令注入
"""
        },
        {
            "name": "安全代码",
            "code": """
def safe_add(a: int, b: int) -> int:
    if not isinstance(a, int) or not isinstance(b, int):
        raise TypeError("Both arguments must be integers")
    return a + b
"""
        }
    ]

    # 运行测试
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{'='*60}")
        print(f"测试 {i}: {test_case['name']}")
        print(f"{'='*60}")
        print(f"\n代码:\n{test_case['code']}")

        result = await detector.detect(test_case['code'])

        print(f"\n检测结果:")
        print(f"  是否存在漏洞: {result.get('has_vulnerability')}")
        print(f"  漏洞类型: {result.get('vulnerability_type')}")
        print(f"  置信度: {result.get('confidence')}")
        print(f"  原因: {result.get('reason')}")

        vuln_lines = result.get('vulnerable_lines', [])
        if vuln_lines:
            print(f"  漏洞行定位:")
            for vl in vuln_lines:
                print(f"    第 {vl.get('line_number', '?')} 行: {vl.get('code', '')}")
                print(f"      说明: {vl.get('explanation', '')}")

        print(f"  RAG检索到 {len(result.get('retrieved_knowledge', []))} 条参考知识")

    print(f"\n{'='*60}")
    print("测试完成！")
    print(f"{'='*60}")


if __name__ == "__main__":
    asyncio.run(test_detection_system())
