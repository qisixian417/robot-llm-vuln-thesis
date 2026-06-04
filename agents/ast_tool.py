# [C9: AST工具] 用tree-sitter解析代码结构，提取危险函数调用/变量/防护检查，注入Detection LLM的prompt以减少幻觉
"""AST-augmented detection tool.

Uses tree-sitter to parse code into structured information before passing
to the Detection LLM. Instead of giving the LLM raw code, we provide:
- List of function calls (especially dangerous ones)
- Variable declarations and their types
- External input markers (function parameters, message callbacks)
- Existing defensive checks (null checks, bounds checks)

This reduces LLM hallucination by giving it pre-computed structural facts,
letting the LLM focus on semantic reasoning rather than syntax parsing.

Requires: pip install tree-sitter-cpp tree-sitter-python
"""

import json
from typing import Dict, Any, List, Optional

from langchain_core.language_models import BaseChatModel


# Dangerous functions to highlight
DANGEROUS_CPP = {
    "strcpy": "CWE-119", "strcat": "CWE-119", "sprintf": "CWE-119",
    "gets": "CWE-119", "scanf": "CWE-119", "memcpy": "CWE-119",
    "system": "CWE-78", "popen": "CWE-78", "exec": "CWE-78",
    "malloc": "CWE-401", "new": "CWE-401", "free": "CWE-416",
    "delete": "CWE-416", "printf": "CWE-134", "fprintf": "CWE-134",
}
DANGEROUS_PYTHON = {
    "os.system": "CWE-78", "subprocess.call": "CWE-78",
    "eval": "CWE-78", "exec": "CWE-78",
    "printf": "CWE-134", "format": "CWE-134",
}

NULL_CHECK_PATTERNS = {"nullptr", "NULL", "null", "None", "!= null", "is None", "is not None"}


def _parse_with_treesitter(code: str, language: str) -> Optional[object]:
    try:
        if language == "C++":
            import tree_sitter_cpp as tscpp
            from tree_sitter import Language, Parser
            lang = Language(tscpp.language())
        elif language == "Python":
            import tree_sitter_python as tspy
            from tree_sitter import Language, Parser
            lang = Language(tspy.language())
        else:
            return None
        parser = Parser(lang)
        return parser.parse(code.encode("utf-8"))
    except Exception:
        return None


def _extract_identifiers_simple(code: str) -> List[str]:
    """Simple regex-based identifier extraction as fallback."""
    import re
    return re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', code)


def extract_ast_features(code: str, language: str) -> Dict[str, Any]:
    """Extract structural features from code using tree-sitter or fallback regex."""
    features = {
        "language": language,
        "function_calls": [],
        "dangerous_calls": [],
        "variables": [],
        "parameters": [],
        "has_null_check": False,
        "has_bounds_check": False,
        "has_free_or_delete": False,
        "lines_of_code": len([l for l in code.splitlines() if l.strip()]),
        "parse_method": "unknown",
    }

    tree = _parse_with_treesitter(code, language)

    if tree is not None:
        features["parse_method"] = "tree-sitter"
        _walk_tree(tree.root_node, code, features, language)
    else:
        # Fallback: regex-based extraction
        features["parse_method"] = "regex"
        _regex_extract(code, features, language)

    return features


def _walk_tree(node, code: str, features: Dict, language: str):
    """Walk AST nodes and extract relevant information."""
    node_type = node.type

    if node_type == "call_expression":
        try:
            call_text = code[node.start_byte:node.end_byte]
            func_name = call_text.split("(")[0].strip().split("->")[-1].split(".")[-1].strip()
            features["function_calls"].append(func_name)
            dangerous = DANGEROUS_CPP if language == "C++" else DANGEROUS_PYTHON
            for danger_fn, cwe in dangerous.items():
                if danger_fn in func_name.lower():
                    features["dangerous_calls"].append({
                        "function": func_name,
                        "cwe_risk": cwe,
                        "line": node.start_point[0] + 1,
                    })
        except Exception:
            pass

    if node_type in ("parameter_declaration", "parameter"):
        try:
            param_text = code[node.start_byte:node.end_byte]
            features["parameters"].append(param_text.strip()[:80])
        except Exception:
            pass

    if node_type in ("declaration", "variable_declarator"):
        try:
            var_text = code[node.start_byte:node.end_byte]
            features["variables"].append(var_text.strip()[:80])
        except Exception:
            pass

    if node_type in ("if_statement", "binary_expression"):
        try:
            text = code[node.start_byte:node.end_byte].lower()
            if any(p in text for p in NULL_CHECK_PATTERNS):
                features["has_null_check"] = True
            if any(kw in text for kw in ("size", "len", "length", "sizeof", "<", ">", "<=")):
                features["has_bounds_check"] = True
        except Exception:
            pass

    if node_type == "call_expression":
        try:
            text = code[node.start_byte:node.end_byte].lower()
            if any(kw in text for kw in ("free", "delete", "close", "fclose")):
                features["has_free_or_delete"] = True
        except Exception:
            pass

    for child in node.children:
        _walk_tree(child, code, features, language)


def _regex_extract(code: str, features: Dict, language: str):
    """Fallback regex extraction."""
    import re
    calls = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', code)
    features["function_calls"] = list(set(calls))
    dangerous = DANGEROUS_CPP if language == "C++" else DANGEROUS_PYTHON
    for call in calls:
        for danger_fn, cwe in dangerous.items():
            if danger_fn in call.lower():
                features["dangerous_calls"].append({"function": call, "cwe_risk": cwe})
    if any(p in code for p in ("nullptr", "NULL", "!= NULL", "is None")):
        features["has_null_check"] = True
    if any(kw in code for kw in ("sizeof", "strlen", "size()", ".length()")):
        features["has_bounds_check"] = True
    params = re.findall(r'\(([^)]{0,200})\)', code)
    if params:
        features["parameters"] = [p.strip() for p in params[0].split(",") if p.strip()]


def format_ast_for_prompt(features: Dict[str, Any]) -> str:
    """Format AST features as readable text for injection into LLM prompt."""
    lines = ["=== Code Structure Analysis ==="]

    if features.get("dangerous_calls"):
        lines.append(f"⚠ DANGEROUS OPERATIONS FOUND:")
        for d in features["dangerous_calls"][:5]:
            lines.append(f"  - {d['function']}() → risk: {d['cwe_risk']}"
                        + (f" (line {d['line']})" if d.get("line") else ""))
    else:
        lines.append("✓ No known dangerous function calls detected")

    if features.get("parameters"):
        lines.append(f"Parameters (potential external input): {', '.join(features['parameters'][:3])}")

    guards = []
    if features.get("has_null_check"):
        guards.append("null check present")
    if features.get("has_bounds_check"):
        guards.append("bounds check present")
    if features.get("has_free_or_delete"):
        guards.append("free/delete present")
    if guards:
        lines.append(f"Defensive checks: {', '.join(guards)}")
    else:
        lines.append("Defensive checks: NONE detected")

    lines.append(f"Lines of code: {features.get('lines_of_code', '?')}")
    lines.append("=== End Analysis ===")
    return "\n".join(lines)


class ASTAugmentedDetector:
    """Detection agent that augments LLM with AST-extracted structural facts."""

    def __init__(self, llm: BaseChatModel, base_detector=None):
        self.llm = llm
        self.base_detector = base_detector

    async def detect(
        self,
        code: str,
        cwe_hint: Optional[str] = None,
        rag_documents: Optional[List] = None,
    ) -> Dict[str, Any]:
        """Run AST extraction then pass enriched context to Detection LLM."""
        language = self._guess_language(code)
        ast_features = extract_ast_features(code, language)
        ast_summary = format_ast_for_prompt(ast_features)

        augmented_code = f"{ast_summary}\n\nOriginal code:\n{code}"

        if self.base_detector:
            result = await self.base_detector.detect(
                code=augmented_code,
                cwe_hint=cwe_hint,
                rag_documents=rag_documents,
            )
        else:
            from agents.vuln_detector import VulnDetectorAgent
            detector = VulnDetectorAgent(llm=self.llm)
            result = await detector.detect(
                code=augmented_code,
                cwe_hint=cwe_hint,
                rag_documents=rag_documents,
            )

        result["ast_dangerous_calls"] = [d["function"] for d in ast_features.get("dangerous_calls", [])]
        result["ast_has_null_check"] = ast_features.get("has_null_check", False)
        result["ast_has_bounds_check"] = ast_features.get("has_bounds_check", False)
        result["ast_parse_method"] = ast_features.get("parse_method", "unknown")
        return result

    def _guess_language(self, code: str) -> str:
        py_signals = ("def ", "import ", "    ", "self.", "elif ")
        if sum(1 for s in py_signals if s in code) >= 2:
            return "Python"
        return "C++"
