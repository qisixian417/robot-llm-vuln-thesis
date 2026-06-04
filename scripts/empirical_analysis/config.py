# [实证分析] 全局配置：数据路径、统计显著性阈值、图表样式设置
"""
配置常量、绘图样式、阈值定义
"""
import matplotlib.pyplot as plt
import matplotlib
import seaborn as sns
from pathlib import Path

# ============================================================================
# 路径配置
# ============================================================================
ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = ROOT / "data"
OUTPUT_DIR = ROOT / "experiments" / "v3"
FIGURES_DIR = OUTPUT_DIR / "figures"

# 确保输出目录存在
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================================
# 数据集路径
# ============================================================================
DATASET_PATH = DATA_DIR / "dataset_final_v2.jsonl"

# ============================================================================
# 统计检验阈值
# ============================================================================
ALPHA = 0.05  # 显著性水平
BOOTSTRAP_N = 10000  # Bootstrap重采样次数
BOOTSTRAP_CI = 0.95  # 置信区间水平
CV_FOLDS = 5  # 交叉验证折数

# ============================================================================
# 效应量解释阈值
# ============================================================================
CLIFF_DELTA_THRESHOLDS = {
    "negligible": 0.147,
    "small": 0.33,
    "medium": 0.474,
    "large": 1.0,
}

COHENS_D_THRESHOLDS = {
    "negligible": 0.2,
    "small": 0.5,
    "medium": 0.8,
    "large": float("inf"),
}

CRAMERS_V_THRESHOLDS = {
    "negligible": 0.1,
    "small": 0.3,
    "medium": 0.5,
    "large": float("inf"),
}

# ============================================================================
# CWE Top 25 2024 参考数据
# ============================================================================
CWE_TOP_25_2024 = {
    "CWE-79": {"rank": 1, "name": "Cross-site Scripting"},
    "CWE-787": {"rank": 2, "name": "Out-of-bounds Write"},
    "CWE-89": {"rank": 3, "name": "SQL Injection"},
    "CWE-78": {"rank": 7, "name": "OS Command Injection"},
    "CWE-476": {"rank": 9, "name": "NULL Pointer Dereference"},
    "CWE-416": {"rank": 10, "name": "Use After Free"},
    "CWE-190": {"rank": 12, "name": "Integer Overflow"},
    "CWE-362": {"rank": 15, "name": "Race Condition"},
    "CWE-119": {"rank": 17, "name": "Buffer Overflow"},
    "CWE-401": {"rank": 32, "name": "Memory Leak"},
    "CWE-134": {"rank": 36, "name": "Format String"},
}

# ============================================================================
# ROS架构层映射（CWE → ROS架构层）
# ============================================================================
CWE_TO_ROS_LAYER = {
    "CWE-476": "资源管理层",   # 空指针 → 节点生命周期资源管理
    "CWE-401": "资源管理层",   # 内存泄漏 → 节点生命周期资源管理
    "CWE-416": "资源管理层",   # UAF → 节点生命周期资源管理
    "CWE-362": "并发层",       # 竞态条件 → 多线程Executor并发回调
    "CWE-119": "输入处理层",   # 缓冲区溢出 → 消息反序列化
    "CWE-190": "输入处理层",   # 整数溢出 → 消息数据处理
    "CWE-78": "输入处理层",    # 命令注入 → 外部输入处理
    "CWE-134": "输入处理层",   # 格式化字符串 → 日志/消息格式化
}

# ============================================================================
# ROS API特征正则表达式
# ============================================================================
ROS_FEATURES = {
    "callback": r"(?i)(create_subscription|create_timer|create_wall_timer|Callback|callback_group|timer_callback)",
    "pub_sub": r"(?i)(create_publisher|create_subscription|advertise|subscribe|Publisher|Subscriber|publish\()",
    "lifecycle": r"(?i)(on_activate|on_deactivate|on_cleanup|on_shutdown|LifecycleNode|on_configure)",
    "parameter": r"(?i)(declare_parameter|get_parameter|set_parameter|param\(|getParam|setParam)",
    "service": r"(?i)(create_service|create_client|ServiceServer|ServiceClient|advertiseService)",
    "action": r"(?i)(create_action|ActionServer|ActionClient|action_server|action_client)",
    "tf": r"(?i)(TransformBroadcaster|TransformListener|lookupTransform|tf2|sendTransform)",
    "threading": r"(?i)(MultiThreadedExecutor|mutex|lock_guard|unique_lock|thread|boost::thread|scoped_lock)",
    "memory_mgmt": r"(?i)(new\s|delete\s|malloc|free|shared_ptr|unique_ptr|make_shared|allocat)",
    "ros_init": r"(?i)(rclcpp::init|rclpy\.init|ros::init|Node\(|rclcpp::Node)",
    "error_handling": r"(?i)(try|catch|throw|except|RCLCPP_ERROR|RCLCPP_WARN|ROS_ERROR|ROS_WARN)",
    "smart_ptr": r"(?i)(shared_ptr|unique_ptr|weak_ptr|make_shared|make_unique)",
}

# ROS API特征 → ROS架构机制映射
FEATURE_TO_MECHANISM = {
    "callback": "异步执行模型（Executor回调调度）",
    "pub_sub": "话题通信机制（无认证的发布/订阅）",
    "lifecycle": "节点生命周期管理",
    "parameter": "参数服务器（运行时配置）",
    "service": "服务通信机制（请求/响应）",
    "action": "动作通信机制（长时任务）",
    "tf": "坐标变换系统（时间同步依赖）",
    "threading": "多线程Executor并发模型",
    "memory_mgmt": "节点生命周期资源管理",
    "ros_init": "节点初始化与注册",
    "error_handling": "错误处理与日志系统",
    "smart_ptr": "智能指针资源管理",
}

# ============================================================================
# 绘图样式配置
# ============================================================================
def setup_plot_style():
    """设置全局绘图样式（论文级别）"""
    matplotlib.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "DejaVu Serif"],
        "font.size": 10,
        "axes.titlesize": 11,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "figure.dpi": 300,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.05,
        "axes.grid": False,
        "axes.spines.top": False,
        "axes.spines.right": False,
    })
    sns.set_palette("colorblind")


# 颜色方案
COLORS = {
    "vulnerable": "#d62728",
    "benign": "#2ca02c",
    "primary": "#1f77b4",
    "secondary": "#ff7f0e",
    "highlight": "#e377c2",
}

# 图片尺寸
FIG_SINGLE_COL = (3.5, 2.8)   # 单栏
FIG_DOUBLE_COL = (7.0, 4.0)   # 双栏
FIG_SQUARE = (4.0, 4.0)       # 正方形
