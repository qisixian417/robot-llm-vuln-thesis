# [模块入口] pipeline包：导出Coordinator（LangGraph状态机调度器）
"""Pipeline package: LangGraph-based multi-agent orchestration."""

from .coordinator import Coordinator, PipelineState

__all__ = ["Coordinator", "PipelineState"]
