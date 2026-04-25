#!/usr/bin/env python3
"""RoboGuard Web界面 - 基于Streamlit"""

import asyncio
import os
import streamlit as st
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

from agents import VulnDetectorAgent
from rag.retriever import RAGRetriever

# 加载环境变量
load_dotenv()

# 页面配置
st.set_page_config(
    page_title="RoboGuard - ROS漏洞检测系统",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 自定义CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #666;
        text-align: center;
        margin-bottom: 2rem;
    }
    .vulnerability-box {
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .vuln-detected {
        background-color: #ffebee;
        border-left: 4px solid #f44336;
    }
    .vuln-safe {
        background-color: #e8f5e9;
        border-left: 4px solid #4caf50;
    }
    .confidence-high {
        color: #4caf50;
        font-weight: bold;
    }
    .confidence-medium {
        color: #ff9800;
        font-weight: bold;
    }
    .confidence-low {
        color: #f44336;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


# 示例代码
EXAMPLES = {
    "缓冲区溢出 (C++)": {
        "code": """void process_message(const char* msg) {
    char buffer[64];
    strcpy(buffer, msg);  // 危险：没有检查长度
    printf("Processed: %s\\n", buffer);
}""",
        "language": "C++"
    },
    "命令注入 (Python)": {
        "code": """def execute_command(user_input):
    import os
    cmd = "ls " + user_input
    os.system(cmd)  # 危险：直接执行用户输入""",
        "language": "Python"
    },
    "内存泄漏 (C++)": {
        "code": """void allocate_memory() {
    char* data = new char[1024];
    if (error_condition) {
        return;  // 内存泄漏：提前返回未释放
    }
    delete[] data;
}""",
        "language": "C++"
    },
    "安全代码 (Python)": {
        "code": """def safe_add(a: int, b: int) -> int:
    if not isinstance(a, int) or not isinstance(b, int):
        raise TypeError("Both arguments must be integers")
    return a + b""",
        "language": "Python"
    }
}


@st.cache_resource
def init_detector():
    """初始化检测器（缓存以提高性能）"""
    try:
        llm = ChatOpenAI(
            model=os.getenv("MODEL_NAME", "qwen-plus"),
            openai_api_key=os.getenv("DASHSCOPE_API_KEY"),
            openai_api_base=os.getenv(
                "MODEL_BASE_URL",
                "https://dashscope.aliyuncs.com/compatible-mode/v1"
            ),
            temperature=0.1,
        )

        rag_retriever = RAGRetriever(persist_dir="./data/chroma_db")
        doc_count = rag_retriever.count()

        detector = VulnDetectorAgent(llm=llm, rag_retriever=rag_retriever)

        return detector, doc_count, None
    except Exception as e:
        return None, 0, str(e)


def display_result(result):
    """显示检测结果"""
    has_vuln = result.get('has_vulnerability', False)
    vuln_type = result.get('vulnerability_type') or 'N/A'
    reason = result.get('reason', '无说明')
    confidence = result.get('confidence', 0.0)
    rag_docs = result.get('retrieved_knowledge', [])

    # 漏洞状态
    if has_vuln:
        st.markdown(f'<div class="vulnerability-box vuln-detected">', unsafe_allow_html=True)
        st.error("⚠️ 检测到安全漏洞")
    else:
        st.markdown(f'<div class="vulnerability-box vuln-safe">', unsafe_allow_html=True)
        st.success("✅ 未检测到明显漏洞")

    # 详细信息
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**漏洞类型:**")
        st.write(vuln_type)

    with col2:
        st.markdown("**置信度:**")
        if confidence >= 0.8:
            st.markdown(f'<span class="confidence-high">{confidence:.2%}</span>', unsafe_allow_html=True)
        elif confidence >= 0.6:
            st.markdown(f'<span class="confidence-medium">{confidence:.2%}</span>', unsafe_allow_html=True)
        else:
            st.markdown(f'<span class="confidence-low">{confidence:.2%}</span>', unsafe_allow_html=True)

    st.markdown("**原因说明:**")
    st.write(reason)

    # 显示漏洞行定位
    vuln_lines = result.get('vulnerable_lines', [])
    if vuln_lines and has_vuln:
        st.markdown("**漏洞行定位:**")
        for vl in vuln_lines:
            line_num = vl.get('line_number', '?')
            line_code = vl.get('code', '')
            line_expl = vl.get('explanation', '')
            st.markdown(
                f'<div style="background-color:#fff3e0;border-left:3px solid #ff9800;'
                f'padding:0.5rem;margin:0.3rem 0;border-radius:0.3rem;">'
                f'<b>第 {line_num} 行:</b> <code>{line_code}</code><br>'
                f'<span style="color:#666;">{line_expl}</span></div>',
                unsafe_allow_html=True
            )

    st.markdown('</div>', unsafe_allow_html=True)

    # RAG检索结果
    if rag_docs:
        with st.expander(f"📚 检索到的参考知识 ({len(rag_docs)} 条)", expanded=False):
            for i, doc in enumerate(rag_docs, 1):
                st.markdown(f"**案例 {i}:**")
                st.code(doc.get('content', '')[:200] + '...', language='text')
                metadata = doc.get('metadata', {})
                if metadata:
                    st.caption(f"CWE: {metadata.get('cwe_id', 'N/A')} | "
                             f"严重性: {metadata.get('severity', 'N/A')} | "
                             f"来源: {metadata.get('repo', 'N/A')}")
                st.divider()


def main():
    # 标题
    st.markdown('<div class="main-header">🛡️ RoboGuard</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">基于RAG增强的ROS函数级安全漏洞检测系统</div>', unsafe_allow_html=True)

    # 侧边栏
    with st.sidebar:
        st.header("⚙️ 系统信息")

        # 初始化检测器
        with st.spinner("正在初始化检测系统..."):
            detector, doc_count, error = init_detector()

        if error:
            st.error(f"❌ 初始化失败: {error}")
            st.info("请确保：\n1. .env文件配置正确\n2. 向量数据库已构建")
            st.stop()

        st.success("✅ 系统就绪")
        st.metric("RAG知识库", f"{doc_count} 个案例")
        st.metric("检测模型", os.getenv("MODEL_NAME", "qwen-plus"))

        st.divider()

        st.header("📖 使用说明")
        st.markdown("""
        1. 在右侧输入要检测的代码
        2. 选择代码语言（C++或Python）
        3. 点击"开始检测"按钮
        4. 查看检测结果和RAG检索的参考案例

        **支持的漏洞类型:**
        - CWE-119: 缓冲区溢出
        - CWE-78: 命令注入
        - CWE-401: 内存泄漏
        - CWE-362: 竞态条件
        - CWE-476: 空指针解引用
        """)

        st.divider()

        st.header("📊 项目信息")
        st.info("""
        **RoboGuard** 是一个基于大语言模型和RAG技术的ROS代码安全检测系统。

        - 检测粒度：函数级
        - 知识增强：595个历史漏洞案例
        - 召回率：100% (vs 静态工具0%)
        """)

    # 主界面
    tab1, tab2 = st.tabs(["🔍 漏洞检测", "📝 示例代码"])

    with tab1:
        # 代码输入
        col1, col2 = st.columns([3, 1])
        with col1:
            st.subheader("输入代码")
        with col2:
            language = st.selectbox("语言", ["C++", "Python"], key="lang_select")

        code_input = st.text_area(
            "请输入要检测的函数代码：",
            height=300,
            placeholder="在此粘贴您的代码...",
            key="code_input"
        )

        # 检测按钮
        col1, col2, col3 = st.columns([1, 1, 2])
        with col1:
            detect_button = st.button("🔍 开始检测", type="primary", use_container_width=True)
        with col2:
            clear_button = st.button("🗑️ 清空", use_container_width=True)

        if clear_button:
            st.rerun()

        # 执行检测
        if detect_button:
            if not code_input.strip():
                st.warning("⚠️ 请先输入代码")
            else:
                with st.spinner("🔍 正在检测中，请稍候..."):
                    try:
                        # 运行异步检测
                        result = asyncio.run(detector.detect(code_input))

                        st.divider()
                        st.subheader("检测结果")
                        display_result(result)

                    except Exception as e:
                        st.error(f"❌ 检测失败: {str(e)}")
                        st.exception(e)

    with tab2:
        st.subheader("示例代码")
        st.write("点击下方按钮快速加载示例代码进行测试：")

        cols = st.columns(2)
        for i, (name, example) in enumerate(EXAMPLES.items()):
            with cols[i % 2]:
                if st.button(name, use_container_width=True, key=f"example_{i}"):
                    st.session_state.code_input = example['code']
                    st.session_state.lang_select = example['language']
                    st.rerun()

        st.divider()

        # 显示所有示例
        for name, example in EXAMPLES.items():
            with st.expander(f"📄 {name}"):
                st.code(example['code'], language=example['language'].lower())


if __name__ == "__main__":
    main()
