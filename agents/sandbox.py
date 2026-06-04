# [C3: Docker沙箱] 在隔离容器中编译运行PoC代码，集成ASan/TSan/UBSan，将LLM漏洞判断升级为运行时物理证据
"""Docker-based sandbox for safely executing PoC code with sanitizers.

The sandbox runs LLM-generated PoC code in an isolated Docker container with:
- Memory/CPU/process limits
- No network access
- Read-only filesystem
- AddressSanitizer (ASan) / ThreadSanitizer (TSan) / UBSan compilation flags

This is the foundation for the Verification Agent.
"""

import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class SandboxResult:
    """Result of running code in sandbox."""
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    compile_failed: bool
    asan_triggered: bool = False
    tsan_triggered: bool = False
    ubsan_triggered: bool = False
    leak_detected: bool = False
    asan_keyword: Optional[str] = None

    def has_runtime_evidence(self) -> bool:
        """True if any sanitizer flagged the execution."""
        return (
            self.asan_triggered
            or self.tsan_triggered
            or self.ubsan_triggered
            or self.leak_detected
        )


# Sanitizer keyword patterns
ASAN_KEYWORDS = [
    "stack-buffer-overflow",
    "heap-buffer-overflow",
    "global-buffer-overflow",
    "heap-use-after-free",
    "stack-use-after-return",
    "stack-use-after-scope",
    "double-free",
    "AddressSanitizer: SEGV",
    "AddressSanitizer: null",
]
TSAN_KEYWORDS = [
    "ThreadSanitizer: data race",
    "ThreadSanitizer: deadlock",
]
UBSAN_KEYWORDS = [
    "runtime error: signed integer overflow",
    "runtime error: unsigned integer overflow",
    "runtime error: shift",
    "runtime error: division by zero",
    "runtime error: load of value",
    "runtime error: store to null pointer",
    "runtime error: load of null pointer",
]
LEAK_KEYWORDS = [
    "LeakSanitizer: detected memory leaks",
    "Direct leak of",
]


def _parse_sanitizer_output(stderr: str) -> dict:
    """Detect which sanitizer(s) triggered."""
    asan_kw = next((kw for kw in ASAN_KEYWORDS if kw in stderr), None)
    tsan_kw = next((kw for kw in TSAN_KEYWORDS if kw in stderr), None)
    ubsan_kw = next((kw for kw in UBSAN_KEYWORDS if kw in stderr), None)
    leak_kw = next((kw for kw in LEAK_KEYWORDS if kw in stderr), None)

    return {
        "asan_triggered": asan_kw is not None,
        "tsan_triggered": tsan_kw is not None,
        "ubsan_triggered": ubsan_kw is not None,
        "leak_detected": leak_kw is not None,
        "asan_keyword": asan_kw or tsan_kw or ubsan_kw or leak_kw,
    }


def _docker_available() -> bool:
    try:
        result = subprocess.run(
            ["docker", "version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def run_cpp_sandbox(
    code: str,
    sanitizer: str = "address",
    timeout: int = 30,
) -> SandboxResult:
    """Compile and run C++ code in Docker sandbox with sanitizer.

    Args:
        code: full C++ source (must include main())
        sanitizer: "address" (ASan), "thread" (TSan), "undefined" (UBSan)
        timeout: max execution time in seconds
    """
    if not _docker_available():
        return _run_locally_fallback(code, sanitizer, timeout, language="cpp")

    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = Path(tmpdir) / "poc.cpp"
        src_path.write_text(code, encoding="utf-8")

        cmd = [
            "docker", "run", "--rm",
            "--memory=512m",
            "--cpus=1",
            "--pids-limit=50",
            "--network=none",
            "-v", f"{tmpdir}:/work:ro",
            "--workdir", "/work",
            "gcc:13",
            "bash", "-c",
            f"g++ -std=c++17 -fsanitize={sanitizer} -g -O0 /work/poc.cpp -o /tmp/a.out 2> /tmp/build.err && "
            f"timeout {timeout} /tmp/a.out; "
            f"ec=$?; "
            f"if [ $ec -ne 0 ] && [ -s /tmp/build.err ]; then cat /tmp/build.err >&2; fi; "
            f"exit $ec",
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout + 30,
                text=True,
                errors="replace",
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                exit_code=-1, stdout="", stderr="Timeout",
                timed_out=True, compile_failed=False,
            )

        compile_failed = "error:" in proc.stderr and proc.returncode != 0 and "AddressSanitizer" not in proc.stderr
        san = _parse_sanitizer_output(proc.stderr)

        return SandboxResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            timed_out=False,
            compile_failed=compile_failed,
            **san,
        )


def run_python_sandbox(code: str, timeout: int = 30) -> SandboxResult:
    """Run Python code in Docker sandbox."""
    if not _docker_available():
        return _run_locally_fallback(code, "none", timeout, language="python")

    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = Path(tmpdir) / "poc.py"
        src_path.write_text(code, encoding="utf-8")

        cmd = [
            "docker", "run", "--rm",
            "--memory=512m",
            "--cpus=1",
            "--pids-limit=50",
            "--network=none",
            "-v", f"{tmpdir}:/work:ro",
            "--workdir", "/work",
            "python:3.11-slim",
            "timeout", str(timeout), "python", "/work/poc.py",
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, timeout=timeout + 30,
                text=True, errors="replace",
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                exit_code=-1, stdout="", stderr="Timeout",
                timed_out=True, compile_failed=False,
            )

        return SandboxResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            timed_out=False,
            compile_failed=False,
        )


def _run_locally_fallback(
    code: str,
    sanitizer: str,
    timeout: int,
    language: str = "cpp",
) -> SandboxResult:
    """Fallback: run without Docker (UNSAFE - only for environments where Docker is unavailable).

    WARNING: This bypasses Docker isolation. Should only be used in trusted dev environments.
    """
    print("[Sandbox] WARNING: Docker not available, falling back to local execution.")
    print("[Sandbox] WARNING: This is unsafe - only use in trusted environments.")

    with tempfile.TemporaryDirectory() as tmpdir:
        if language == "cpp":
            src_path = Path(tmpdir) / "poc.cpp"
            src_path.write_text(code, encoding="utf-8")
            bin_path = Path(tmpdir) / "a.out"

            try:
                build = subprocess.run(
                    ["g++", "-std=c++17", f"-fsanitize={sanitizer}", "-g", "-O0",
                     str(src_path), "-o", str(bin_path)],
                    capture_output=True, text=True, timeout=60, errors="replace",
                )
                if build.returncode != 0:
                    return SandboxResult(
                        exit_code=build.returncode,
                        stdout="", stderr=build.stderr,
                        timed_out=False, compile_failed=True,
                    )
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                return SandboxResult(
                    exit_code=-1, stdout="", stderr=f"Build failed: {e}",
                    timed_out=False, compile_failed=True,
                )

            try:
                proc = subprocess.run(
                    [str(bin_path)],
                    capture_output=True, timeout=timeout, text=True, errors="replace",
                )
            except subprocess.TimeoutExpired:
                return SandboxResult(
                    exit_code=-1, stdout="", stderr="Timeout",
                    timed_out=True, compile_failed=False,
                )
        else:
            src_path = Path(tmpdir) / "poc.py"
            src_path.write_text(code, encoding="utf-8")
            try:
                proc = subprocess.run(
                    ["python", str(src_path)],
                    capture_output=True, timeout=timeout, text=True, errors="replace",
                )
            except subprocess.TimeoutExpired:
                return SandboxResult(
                    exit_code=-1, stdout="", stderr="Timeout",
                    timed_out=True, compile_failed=False,
                )

        san = _parse_sanitizer_output(proc.stderr)
        return SandboxResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            timed_out=False,
            compile_failed=False,
            **san,
        )
