#!/bin/bash
# RoboGuard Web界面启动脚本

echo "=========================================="
echo "  RoboGuard - ROS漏洞检测系统"
echo "=========================================="
echo ""

# 检查环境
if [ ! -f ".env" ]; then
    echo "❌ 错误：.env文件不存在"
    echo "请先配置.env文件（参考.env.example）"
    exit 1
fi

if [ ! -d "data/chroma_db" ]; then
    echo "⚠️  警告：向量数据库不存在"
    echo "建议先运行: python3 scripts/build_chroma_db.py --reset"
    echo ""
fi

# 启动Streamlit
echo "🚀 正在启动Web界面..."
echo "📍 访问地址: http://localhost:8501"
echo ""
echo "按 Ctrl+C 停止服务"
echo ""

STREAMLIT_SERVER_HEADLESS=true streamlit run app.py \
    --server.port 8501 \
    --server.address localhost \
    --browser.gatherUsageStats false
