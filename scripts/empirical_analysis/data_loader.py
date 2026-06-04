# [实证分析] 数据加载器：从JSONL读取数据集，统一格式供各RQ模块使用
"""
数据加载与预处理模块
"""
import json
import re
from pathlib import Path
from typing import Dict, List, Any
from collections import Counter

from .config import DATASET_PATH, ROS_FEATURES


def load_jsonl(path: Path = None) -> List[Dict[str, Any]]:
    """加载JSONL数据集"""
    path = path or DATASET_PATH
    items = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items


def compute_code_metrics(code: str) -> Dict[str, Any]:
    """计算代码复杂度指标"""
    lines = code.split('\n')

    # LOC: 总行数
    loc = len(lines)

    # SLOC: 非空非注释行数
    sloc = 0
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('#') and not stripped.startswith('//'):
            sloc += 1

    # 函数调用数
    num_functions_called = len(re.findall(r'\w+\s*\(', code))

    # 最大嵌套深度
    max_nesting = 0
    current_nesting = 0
    for char in code:
        if char == '{':
            current_nesting += 1
            max_nesting = max(max_nesting, current_nesting)
        elif char == '}':
            current_nesting = max(0, current_nesting - 1)

    # 条件语句数量
    num_conditions = len(re.findall(r'\b(if|else|elif|switch|while|for)\b', code))

    # 圈复杂度（近似）
    cyclomatic_complexity = num_conditions + 1

    # 指针使用（C++）
    num_pointers = len(re.findall(r'(\*|->)', code))

    # 是否有内存分配
    has_allocation = bool(re.search(r'\b(new|malloc|calloc)\b', code))

    # 是否有线程相关
    has_threading = bool(re.search(r'\b(mutex|lock|thread)\b', code, re.IGNORECASE))

    return {
        'loc': loc,
        'sloc': sloc,
        'num_functions_called': num_functions_called,
        'max_nesting_depth': max_nesting,
        'num_conditions': num_conditions,
        'cyclomatic_complexity': cyclomatic_complexity,
        'num_pointers': num_pointers,
        'has_allocation': has_allocation,
        'has_threading': has_threading,
    }


def extract_ros_features(code: str) -> Dict[str, bool]:
    """提取代码中的ROS API特征"""
    features = {}
    for feat_name, feat_regex in ROS_FEATURES.items():
        features[feat_name] = bool(re.search(feat_regex, code))
    return features


def preprocess_samples(samples: List[Dict]) -> List[Dict]:
    """预处理样本：添加计算字段"""
    for s in samples:
        code = s.get("vulnerable_code", "")
        s["_metrics"] = compute_code_metrics(code)
        s["_features"] = extract_ros_features(code)
        s["_label"] = int(s.get("label", 0))
        s["_cwe"] = s.get("cwe_id") or "unknown"
        s["_language"] = s.get("language", "unknown")
        s["_component"] = s.get("ros_component", "other")
        s["_ros_version"] = s.get("ros_version", "other")
        s["_severity"] = s.get("severity", "MEDIUM") or "MEDIUM"
        s["_repo"] = s.get("repo", "unknown")
    return samples


def split_by_label(samples: List[Dict]) -> tuple:
    """按标签分割样本"""
    vuln = [s for s in samples if s["_label"] == 1]
    benign = [s for s in samples if s["_label"] == 0]
    return vuln, benign


def get_dataset_summary(samples: List[Dict]) -> Dict:
    """获取数据集概要统计"""
    vuln, benign = split_by_label(samples)
    return {
        "total": len(samples),
        "vulnerable": len(vuln),
        "benign": len(benign),
        "vuln_ratio": len(vuln) / len(samples) if samples else 0,
        "languages": dict(Counter(s["_language"] for s in samples)),
        "components": dict(Counter(s["_component"] for s in samples)),
        "cwe_types": dict(Counter(s["_cwe"] for s in vuln)),
        "ros_versions": dict(Counter(s["_ros_version"] for s in samples)),
        "severities": dict(Counter(s["_severity"] for s in vuln)),
        "repos": len(set(s["_repo"] for s in samples)),
    }


def convert_to_native(obj):
    """转换numpy类型为Python原生类型，用于JSON序列化"""
    if isinstance(obj, dict):
        return {k: convert_to_native(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_native(item) for item in obj]
    elif isinstance(obj, tuple):
        return [convert_to_native(item) for item in obj]
    elif hasattr(obj, 'item'):  # numpy types
        return obj.item()
    elif isinstance(obj, (int, float, str, type(None), bool)):
        return obj
    else:
        return str(obj)
