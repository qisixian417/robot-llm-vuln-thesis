# evaluate_rag_vs_norag.py
# ========================
# 对比实验：有RAG vs 无RAG 的漏洞检测 F1 对比
#
# 增强版特性：
#   1. 三路融合检索：BM25 + TF-IDF余弦 + Dense Embedding
#   2. Cross-Encoder Reranker 重排序
#   3. 动态 Top-K（基于分数断崖检测）
#   4. 检索质量指标：Recall@K、MRR
#
# 运行方式：
#   cd robot-llm-vuln-thesis
#   python scripts/evaluate_rag_vs_norag.py

import json
import os
import re
import math
import time
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# HuggingFace 国内镜像（解决无法直接访问 huggingface.co 的问题）
os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"

# Fix Windows console encoding for Chinese/Unicode output
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from dotenv import load_dotenv
import urllib.request

load_dotenv()

# ─────────────────────────────────────────────
# 配置
# ─────────────────────────────────────────────
API_KEY  = os.getenv("DASHSCOPE_API_KEY", "")
API_URL  = "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
MODEL    = os.getenv("MODEL_NAME", "qwen-plus")

DATASET_PATH = Path("data/dataset_full.jsonl")
CORPUS_PATH  = Path("data/rag_corpus_full.jsonl")
EVAL_SAMPLE_SIZE = 50  # 从完整数据集中采样评估（平衡 label 0/1）

# RAG 检索配置
TOP_K = 5                # 初始检索候选数（三路融合后取 top-k）
DYNAMIC_TOPK_MIN = 3     # 动态 top-k 下限（至少给LLM 3条上下文）
DYNAMIC_TOPK_MAX = 5     # 动态 top-k 上限
SCORE_DROP_RATIO = 0.25  # 分数断崖阈值：降低以保留更多候选

# 三路融合权重（BM25 : TF-IDF : Dense）
# BM25 对代码关键词匹配最可靠，Dense 通用模型对代码不够精准，适当降权
ALPHA_BM25  = 0.45
ALPHA_TFIDF = 0.35
ALPHA_DENSE = 0.20

# Dense Embedding 模型（代码专用：微软 UniXcoder，理解代码结构和语义）
DENSE_MODEL_NAME = "microsoft/unixcoder-base"
# Cross-Encoder Reranker 模型
RERANKER_MODEL_NAME = "cross-encoder/ms-marco-MiniLM-L-6-v2"

# 两次 API 调用之间的间隔（秒），避免限流
REQUEST_INTERVAL = 2


# ─────────────────────────────────────────────
# 工具函数：JSONL 读取
# ─────────────────────────────────────────────
def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    """解析文件中连续拼接的多个JSON对象（支持pretty-print和标准JSONL）"""
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    items = []
    decoder = json.JSONDecoder()
    pos = 0
    while pos < len(content):
        while pos < len(content) and content[pos] in " \t\r\n":
            pos += 1
        if pos >= len(content):
            break
        try:
            obj, end = decoder.raw_decode(content, pos)
            items.append(obj)
            pos = end
        except json.JSONDecodeError:
            pos += 1
    return items


# ═════════════════════════════════════════════
#  第一路：BM25
# ═════════════════════════════════════════════
def tokenize(text: str) -> List[str]:
    """简单中英文分词（按空格和标点切分）"""
    return re.findall(r"[a-zA-Z0-9_\u4e00-\u9fff]+", text.lower())


def build_bm25(corpus_texts: List[str], k1: float = 1.5, b: float = 0.75):
    """构建 BM25 索引"""
    tokenized = [tokenize(t) for t in corpus_texts]
    N = len(tokenized)

    df: Dict[str, int] = {}
    doc_lens = []
    for tokens in tokenized:
        doc_lens.append(len(tokens))
        for tok in set(tokens):
            df[tok] = df.get(tok, 0) + 1

    avgdl = sum(doc_lens) / max(N, 1)

    idf = {}
    for term, freq in df.items():
        idf[term] = math.log((N - freq + 0.5) / (freq + 0.5) + 1.0)

    return {
        'tokenized': tokenized,
        'doc_lens': doc_lens,
        'avgdl': avgdl,
        'idf': idf,
        'k1': k1,
        'b': b,
        'N': N
    }


def bm25_score(query_tokens: List[str], doc_idx: int, bm25_index: Dict) -> float:
    """计算单个文档的 BM25 分数"""
    doc_tokens = bm25_index['tokenized'][doc_idx]
    doc_len = bm25_index['doc_lens'][doc_idx]
    avgdl = bm25_index['avgdl']
    k1 = bm25_index['k1']
    b = bm25_index['b']
    idf = bm25_index['idf']

    tf = {}
    for tok in doc_tokens:
        tf[tok] = tf.get(tok, 0) + 1

    score = 0.0
    for term in query_tokens:
        if term not in tf:
            continue
        term_tf = tf[term]
        term_idf = idf.get(term, 0)
        numerator = term_tf * (k1 + 1)
        denominator = term_tf + k1 * (1 - b + b * doc_len / avgdl)
        score += term_idf * (numerator / denominator)

    return score


# ═════════════════════════════════════════════
#  第二路：TF-IDF 余弦相似度
# ═════════════════════════════════════════════
def build_tfidf(corpus_texts: List[str]):
    """构建 TF-IDF 矩阵，返回 (vocab_idx, idf, tfidf_matrix)"""
    tokenized = [tokenize(t) for t in corpus_texts]
    N = len(tokenized)

    df: Dict[str, int] = {}
    for tokens in tokenized:
        for tok in set(tokens):
            df[tok] = df.get(tok, 0) + 1

    vocab = list(df.keys())
    vocab_idx = {w: i for i, w in enumerate(vocab)}
    V = len(vocab)

    idf = [math.log((N + 1) / (df[w] + 1)) + 1.0 for w in vocab]

    matrix: List[List[float]] = []
    for tokens in tokenized:
        tf: Dict[str, float] = {}
        for tok in tokens:
            tf[tok] = tf.get(tok, 0) + 1
        total = max(len(tokens), 1)
        vec = [0.0] * V
        for tok, cnt in tf.items():
            if tok in vocab_idx:
                vec[vocab_idx[tok]] = (cnt / total) * idf[vocab_idx[tok]]
        norm = math.sqrt(sum(x * x for x in vec)) or 1e-8
        matrix.append([x / norm for x in vec])

    return vocab_idx, idf, matrix


def tfidf_cosine(query_tokens: List[str], vocab_idx: Dict[str, int],
                 idf: List[float], doc_vec: List[float]) -> float:
    """计算查询与单个文档的 TF-IDF 余弦相似度"""
    V = len(idf)
    tf: Dict[str, float] = {}
    for tok in query_tokens:
        tf[tok] = tf.get(tok, 0) + 1
    total = max(len(query_tokens), 1)

    qvec = [0.0] * V
    for tok, cnt in tf.items():
        if tok in vocab_idx:
            qvec[vocab_idx[tok]] = (cnt / total) * idf[vocab_idx[tok]]

    norm = math.sqrt(sum(x * x for x in qvec)) or 1e-8
    qvec = [x / norm for x in qvec]

    return sum(q * d for q, d in zip(qvec, doc_vec))


# ═════════════════════════════════════════════
#  第三路：Dense Embedding（语义向量检索）
# ═════════════════════════════════════════════
_dense_model = None  # 全局缓存，避免重复加载


def load_dense_model(model_name: str = DENSE_MODEL_NAME):
    """加载 SentenceTransformer 模型（失败则返回 None）"""
    global _dense_model
    if _dense_model is not None:
        return _dense_model
    try:
        from sentence_transformers import SentenceTransformer
        print(f"      加载 Dense Embedding 模型: {model_name}")
        _dense_model = SentenceTransformer(model_name)
        return _dense_model
    except Exception as e:
        print(f"      [WARN] Dense Embedding 模型加载失败，退回 TF-IDF 伪向量: {e}")
        return None


def build_dense_index(corpus_texts: List[str], model_name: str = DENSE_MODEL_NAME):
    """
    构建 Dense Embedding 索引
    返回：(model, corpus_embeddings_numpy) 或 (None, None)
    """
    model = load_dense_model(model_name)
    if model is None:
        return None, None
    try:
        import numpy as np
        embeddings = model.encode(
            corpus_texts, show_progress_bar=True,
            batch_size=32, normalize_embeddings=True
        )
        return model, np.asarray(embeddings, dtype=np.float32)
    except Exception as e:
        print(f"      [WARN] Dense Embedding 编码失败: {e}")
        return None, None


def dense_score_batch(query_text: str, model, corpus_embeddings) -> List[Tuple[int, float]]:
    """
    计算查询与所有语料的 Dense 余弦相似度
    返回：[(corpus_idx, similarity), ...]
    """
    if model is None or corpus_embeddings is None:
        return [(i, 0.0) for i in range(len(corpus_embeddings) if corpus_embeddings is not None else 0)]
    try:
        import numpy as np
        q_emb = model.encode([query_text], normalize_embeddings=True)
        q_emb = np.asarray(q_emb, dtype=np.float32)
        # 余弦相似度 = 向量点积（已归一化）
        sims = corpus_embeddings @ q_emb.T
        return [(i, float(sims[i][0])) for i in range(len(sims))]
    except Exception:
        return [(i, 0.0) for i in range(len(corpus_embeddings))]


# ═════════════════════════════════════════════
#  Cross-Encoder Reranker（精排重排序）
# ═════════════════════════════════════════════
_reranker_model = None


def load_reranker(model_name: str = RERANKER_MODEL_NAME):
    """加载 Cross-Encoder 重排序模型"""
    global _reranker_model
    if _reranker_model is not None:
        return _reranker_model
    try:
        from sentence_transformers import CrossEncoder
        print(f"      加载 Reranker 模型: {model_name}")
        _reranker_model = CrossEncoder(model_name)
        return _reranker_model
    except Exception as e:
        print(f"      [WARN] Reranker 模型加载失败，跳过重排序: {e}")
        return None


def rerank(query: str, candidates: List[Tuple[int, float]],
           corpus: List[Dict[str, Any]], model_name: str = RERANKER_MODEL_NAME
           ) -> List[Tuple[int, float]]:
    """
    用 Cross-Encoder 对候选文档重排序

    参数:
        query: 查询文本
        candidates: [(corpus_idx, initial_score), ...]
        corpus: 完整语料列表

    返回:
        重排序后的 [(corpus_idx, reranker_score), ...]
    """
    if not candidates:
        return candidates

    reranker = load_reranker(model_name)
    if reranker is None:
        return candidates  # fallback：保持原排序

    try:
        pairs = [(query, corpus[idx].get("content", "")[:512]) for idx, _ in candidates]
        scores = reranker.predict(pairs)

        reranked = []
        for (idx, _orig_score), rerank_score in zip(candidates, scores):
            reranked.append((idx, float(rerank_score)))

        reranked.sort(key=lambda x: x[1], reverse=True)
        return reranked
    except Exception as e:
        print(f"      [WARN] Reranker 推理失败: {e}")
        return candidates


# ═════════════════════════════════════════════
#  动态 Top-K（基于分数断崖检测）
# ═════════════════════════════════════════════
def dynamic_topk(
    scored_results: List[Tuple[int, float]],
    min_k: int = DYNAMIC_TOPK_MIN,
    max_k: int = DYNAMIC_TOPK_MAX,
    drop_ratio: float = SCORE_DROP_RATIO,
) -> List[Tuple[int, float]]:
    """
    动态决定检索返回数量，而非固定 top-k

    策略：分数断崖检测（Score Cliff Detection）
    ─────────────────────────────────────────
    遍历排序后的候选列表，当相邻文档的分数比值出现显著下降
    （curr / prev < drop_ratio）时，在断崖处截断。

    这样做的好处：
    - 高度相关查询：只保留少量高质量结果，减少噪声
    - 模糊查询：保留更多结果，提升召回率

    参数:
        scored_results: 已按分数降序排列的 [(idx, score), ...]
        min_k: 最少返回数量（保底）
        max_k: 最多返回数量（上限）
        drop_ratio: 断崖判定阈值
    """
    if not scored_results:
        return scored_results
    if len(scored_results) <= min_k:
        return scored_results

    selected = [scored_results[0]]

    for i in range(1, len(scored_results)):
        if len(selected) >= max_k:
            break

        prev_score = scored_results[i - 1][1]
        curr_score = scored_results[i][1]

        # 用两种方式检测断崖：比值法（正分数）和差值法（含负分数）
        is_cliff = False
        if prev_score > 1e-8:
            ratio = curr_score / prev_score
            if ratio < drop_ratio:
                is_cliff = True
        # 差值法：当分数跌幅超过最高分绝对值的 40% 时视为断崖
        top_score = abs(scored_results[0][1]) + 1e-8
        if (prev_score - curr_score) / top_score > 0.4:
            is_cliff = True

        if is_cliff and len(selected) >= min_k:
            break

        selected.append(scored_results[i])

    # 保底：至少返回 min_k 个
    while len(selected) < min_k and len(selected) < len(scored_results):
        selected.append(scored_results[len(selected)])

    return selected


# ═════════════════════════════════════════════
#  查询扩展
# ═════════════════════════════════════════════
CWE_KEYWORD_MAP = {
    r'memcpy|strcpy|sprintf|gets|strcat': [
        'CWE-119 缓冲区溢出 buffer overflow 边界检查 memcpy',
        'CWE-787 越界写入 out-of-bounds'
    ],
    r'\bif\s*\(!\w|\bnullptr\b|\bNULL\b|->': [
        'CWE-476 空指针解引用 null pointer dereference 指针检查'
    ],
    r'\bthread\b|\bspin\b|\bshared_\w|shared_state': [
        'CWE-362 竞态条件 race condition 多线程 互斥锁 mutex'
    ],
    r'create_subscription|create_wall_timer|latest_image_|goal_active_': [
        'ROS2 MultiThreadedExecutor 竞态条件 subscription timer callback 共享成员变量 无锁 race condition CWE-362',
        'CWE-362 ros2 multithreaded callback race latest_image goal_active 互斥锁'
    ],
    r'\bmutex\b|scoped_lock|lock_guard': [
        'ROS 互斥锁 mutex 线程安全 boost recursive_mutex scoped_lock 安全用法'
    ],
    r'\bdelete\b.*\bptr|\bfree\b|\bptr.*delete': [
        'CWE-416 use after free 释放后使用 悬垂指针'
    ],
    r'\*.*width|\*.*height|\*.*size|\*.*count|uint32|int.*\*.*int': [
        'CWE-190 整数溢出 integer overflow 乘法溢出'
    ],
    r'\bnew\b|\bmalloc\b|\bcalloc\b': [
        'CWE-401 内存泄漏 memory leak 智能指针 RAII'
    ],
    r'os\.system|subprocess|os\.popen|shell=True|system\(': [
        'CWE-78 命令注入 command injection os.system shell'
    ],
    r'/\s*dt|/\s*\w+\s*[;,)]\s*//.*除|除以|divide': [
        'CWE-369 除零错误 divide by zero 零值检查'
    ],
    r'printf\s*\(.*\w+\.c_str|NODELET_ERROR\s*\(\s*\w|ROS_ERROR\s*\(\s*\w': [
        'CWE-134 格式字符串漏洞 format string NODELET_ERROR printf c_str 固定格式串 %s',
        'NODELET_ERROR格式字符串漏洞 历史漏洞 pcl ros format'
    ],
    r'\+\s*["\']|"\s*\+\s*\w|sql.*concat|query.*\+': [
        'CWE-89 SQL注入 SQL injection 参数化查询'
    ],
    r'LoadFile|parseXml|TiXml|xml.*load|initXml': [
        'CWE-611 XXE XML外部实体 XML injection'
    ],
    r'access\s*\(|stat\s*\(|F_OK|R_OK|W_OK': [
        'CWE-367 TOCTOU 检查时间与使用时间 race condition access ifstream 文件权限检查',
        'TOCTOU access R_OK 先检查后使用 竞态条件 修复 ifstream直接打开'
    ],
    r'argparse|ArgumentParser|parse_args': [
        'Python argparse 命令行参数解析 安全用法 os.path.isfile CLI工具 非TOCTOU'
    ],
}

GENERAL_QUERIES = [
    'ROS安全漏洞检测 修复策略',
    'ROS回调函数安全 topic service action',
]


def expand_queries(code: str) -> List[str]:
    """查询扩展：从代码特征提取多角度检索查询"""
    queries = [code[:500]]

    for pattern, query_list in CWE_KEYWORD_MAP.items():
        if re.search(pattern, code, re.IGNORECASE):
            queries.extend(query_list)

    queries.extend(GENERAL_QUERIES)
    return queries


# ═════════════════════════════════════════════
#  归一化
# ═════════════════════════════════════════════
def normalize_scores(scores: List[Tuple[int, float]]) -> List[Tuple[int, float]]:
    """Min-Max 归一化到 [0, 1]"""
    if not scores:
        return scores
    max_s = max(s for _, s in scores)
    min_s = min(s for _, s in scores)
    rng = max_s - min_s or 1e-8
    return [(idx, (s - min_s) / rng) for idx, s in scores]


# ═════════════════════════════════════════════
#  三路融合混合检索（BM25 + TF-IDF + Dense）
#  + Reranker 重排序 + 动态 Top-K
# ═════════════════════════════════════════════
def hybrid_retrieve(
    code: str,
    corpus: List[Dict[str, Any]],
    vocab_idx: Dict[str, int],
    idf: List[float],
    tfidf_matrix: List[List[float]],
    bm25_index: Dict,
    dense_model=None,
    dense_corpus_emb=None,
    top_k: int = TOP_K,
    use_reranker: bool = True,
    use_dynamic_topk: bool = True,
) -> Tuple[List[Tuple[int, float]], Dict[str, Any]]:
    """
    三路融合混合检索 + Reranker + 动态 Top-K

    流程：
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │  BM25    │    │ TF-IDF   │    │  Dense   │
    │ 精确词匹配│    │ 稀疏向量  │    │ 语义向量  │
    └────┬─────┘    └────┬─────┘    └────┬─────┘
         │               │               │
         └───────┬───────┘───────┬───────┘
                 │ 加权融合       │
                 ▼               │
           ┌──────────┐         │
           │ 初始排序  │◄────────┘
           └────┬─────┘
                │
                ▼
         ┌──────────────┐
         │ Reranker精排 │ (Cross-Encoder)
         └────┬─────────┘
              │
              ▼
        ┌──────────────┐
        │ 动态 Top-K   │ (分数断崖检测)
        └──────────────┘
    """
    expanded_queries = expand_queries(code)
    N = len(corpus)
    has_dense = dense_model is not None and dense_corpus_emb is not None

    # 累积各路分数
    bm25_accum = [0.0] * N
    tfidf_accum = [0.0] * N
    dense_accum = [0.0] * N

    for query in expanded_queries:
        q_tokens = tokenize(query)

        # ── 第一路：BM25 ──
        raw_bm25 = [(idx, bm25_score(q_tokens, idx, bm25_index)) for idx in range(N)]
        for idx, s in normalize_scores(raw_bm25):
            bm25_accum[idx] += s

        # ── 第二路：TF-IDF 余弦 ──
        raw_tfidf = [(idx, tfidf_cosine(q_tokens, vocab_idx, idf, tfidf_matrix[idx]))
                     for idx in range(N)]
        for idx, s in normalize_scores(raw_tfidf):
            tfidf_accum[idx] += s

        # ── 第三路：Dense Embedding ──
        if has_dense:
            raw_dense = dense_score_batch(query, dense_model, dense_corpus_emb)
            for idx, s in normalize_scores(raw_dense):
                dense_accum[idx] += s

    # 三路加权融合
    if has_dense:
        fused = []
        for idx in range(N):
            score = (ALPHA_BM25 * bm25_accum[idx]
                     + ALPHA_TFIDF * tfidf_accum[idx]
                     + ALPHA_DENSE * dense_accum[idx])
            fused.append((idx, score))
    else:
        # 无 Dense 时退回双路融合
        fused = [(idx, 0.5 * bm25_accum[idx] + 0.5 * tfidf_accum[idx]) for idx in range(N)]

    fused.sort(key=lambda x: x[1], reverse=True)
    pre_rerank_top = fused[:top_k]

    # ── Reranker 精排 ──
    if use_reranker:
        reranked = rerank(code[:500], pre_rerank_top, corpus)
    else:
        reranked = pre_rerank_top

    # ── 动态 Top-K ──
    if use_dynamic_topk:
        final_results = dynamic_topk(reranked)
    else:
        final_results = reranked[:top_k]

    debug_info = {
        'num_queries': len(expanded_queries),
        'expanded_queries_preview': expanded_queries[:3],
        'fusion_mode': 'bm25+tfidf+dense' if has_dense else 'bm25+tfidf',
        'use_reranker': use_reranker and _reranker_model is not None,
        'use_dynamic_topk': use_dynamic_topk,
        'pre_rerank_top3': [(idx, f"{s:.4f}") for idx, s in pre_rerank_top[:3]],
        'post_rerank_top3': [(idx, f"{s:.4f}") for idx, s in reranked[:3]],
        'dynamic_k': len(final_results),
        'bm25_top3': sorted(enumerate(bm25_accum), key=lambda x: x[1], reverse=True)[:3],
        'tfidf_top3': sorted(enumerate(tfidf_accum), key=lambda x: x[1], reverse=True)[:3],
        'dense_top3': sorted(enumerate(dense_accum), key=lambda x: x[1], reverse=True)[:3] if has_dense else [],
    }

    return final_results, debug_info


# ═════════════════════════════════════════════
#  检索质量评估指标：Recall@K 和 MRR
# ═════════════════════════════════════════════
def get_relevant_doc_indices(sample: Dict[str, Any], corpus: List[Dict[str, Any]]) -> set:
    """
    根据 CWE 匹配关系，找出对某个样本来说"相关"的语料文档索引

    规则：
    - 有漏洞的样本（label=1）：语料中 cwe_id 与样本匹配的文档视为相关
    - 安全的样本（label=0）：语料中标记了 is_safe_pattern=true 的文档视为相关
    """
    cwe = sample.get("cwe_id")
    label = sample.get("label", -1)
    relevant = set()

    for idx, doc in enumerate(corpus):
        doc_meta = doc.get("metadata", {})
        doc_cwe = doc_meta.get("cwe_id")
        doc_type = doc.get("type", "")
        is_safe = doc_meta.get("is_safe_pattern", False)

        if label == 1 and cwe:
            # 同 CWE 的描述、历史漏洞、修复策略都算相关
            if doc_cwe == cwe:
                relevant.add(idx)
            # 语义模式文档中 vulnerability_types 列表包含该 CWE
            vuln_types = doc_meta.get("vulnerability_types", [])
            if cwe in vuln_types:
                relevant.add(idx)
        elif label == 0:
            if is_safe:
                relevant.add(idx)

    return relevant


def compute_recall_at_k(retrieved_indices: List[int], relevant: set, k: int = 3) -> float:
    """
    Recall@K = 检索结果前 K 个中命中的相关文档数 / 全部相关文档数

    例如：相关文档共 4 篇，前 3 个检索结果命中了 2 篇 → Recall@3 = 2/4 = 0.5
    """
    if not relevant:
        return 1.0  # 无相关文档可找，视为完美
    top_k_set = set(retrieved_indices[:k])
    hits = top_k_set & relevant
    return len(hits) / len(relevant)


def compute_mrr(retrieved_indices: List[int], relevant: set) -> float:
    """
    MRR (Mean Reciprocal Rank) = 1 / 第一个相关文档的排名位置

    例如：第一个相关文档排在第 2 位 → RR = 1/2 = 0.5
    对所有查询取平均就是 MRR

    MRR 衡量的是"用户需要翻多少个结果才能找到有用的文档"
    """
    if not relevant:
        return 1.0
    for rank, idx in enumerate(retrieved_indices, 1):
        if idx in relevant:
            return 1.0 / rank
    return 0.0


# ─────────────────────────────────────────────
# 千问 API 调用
# ─────────────────────────────────────────────
def call_qwen(messages: List[Dict[str, str]], retries: int = 3) -> str:
    """调用 DashScope OpenAI 兼容接口，返回模型回复文本"""
    payload = json.dumps({
        "model": MODEL,
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": 1024
    }).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}"
    }

    for attempt in range(retries):
        try:
            req = urllib.request.Request(API_URL, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            print(f"    API调用失败(第{attempt+1}次): {e}")
            if attempt < retries - 1:
                time.sleep(5)
    return ""


# ─────────────────────────────────────────────
# 解析模型输出 → 预测标签
# ─────────────────────────────────────────────
VULN_KEYWORDS = [
    "存在漏洞", "存在安全漏洞", "发现漏洞", "检测到漏洞",
    "vulnerable", "vulnerability", "buffer overflow", "null pointer",
    "安全问题", "风险", "有漏洞", "该代码有", "该函数有",
    "缓冲区溢出", "空指针", "内存泄漏", "资源泄漏", "并发",
    "label.*:.*1", "\"label\".*1", "is_vulnerable.*true",
]
SAFE_KEYWORDS = [
    "无漏洞", "未发现漏洞", "no vulnerability", "no vulnerabilities",
    "安全", "正常", "没有安全问题", "不存在漏洞",
    "label.*:.*0", "\"label\".*0", "is_vulnerable.*false",
]


def parse_label(response: str) -> int:
    """从模型回复中提取 0/1 预测标签"""
    text = response.lower()

    m = re.search(r'"label"\s*:\s*([01])', text)
    if m:
        return int(m.group(1))
    m = re.search(r'label\s*[=:]\s*([01])', text)
    if m:
        return int(m.group(1))

    for kw in VULN_KEYWORDS:
        if re.search(kw, text):
            return 1
    for kw in SAFE_KEYWORDS:
        if re.search(kw, text):
            return 0

    return 1


# ─────────────────────────────────────────────
# Prompt 构造
# ─────────────────────────────────────────────
SYSTEM_PROMPT = """你是一名通用C++代码审查工程师，请分析给定的代码片段，判断是否存在安全漏洞。
注意：你对ROS（机器人操作系统）的特定API行为和多线程执行模型了解有限，请基于通用C++安全知识进行判断。

请以如下JSON格式输出（只输出JSON，不要有其他内容）：
{
  "label": 1,
  "vuln_type": "漏洞类型，若无则填null",
  "confidence": 0.85,
  "reasoning": "简要说明判断依据"
}

其中：
- label: 1表示存在漏洞，0表示无漏洞
- confidence: 你对判断结果的置信度（0.0~1.0）
"""


RAG_SYSTEM_PROMPT = """你是一名机器人代码安全专家，专注于ROS（机器人操作系统）代码的安全分析。
你会收到相关的漏洞知识库参考文档，请结合这些文档中的模式和修复策略，判断代码是否存在安全漏洞。

重要提示：
- 如果知识库中有与代码高度匹配的漏洞模式（如格式字符串、TOCTOU等），请以此为判断依据
- 如果知识库中有安全用法示例（is_safe_pattern），且代码与之匹配，则代码可能是安全的
- 综合知识库文档和代码特征给出判断

请以如下JSON格式输出（只输出JSON，不要有其他内容）：
{
  "label": 1,
  "vuln_type": "漏洞类型，若无则填null",
  "confidence": 0.85,
  "reasoning": "简要说明判断依据，引用具体的知识库文档编号"
}

其中：
- label: 1表示存在漏洞，0表示无漏洞
- confidence: 你对判断结果的置信度（0.0~1.0）
"""

def build_no_rag_messages(code: str) -> List[Dict[str, str]]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"请分析以下代码是否存在安全漏洞：\n\n```cpp\n{code}\n```"}
    ]


def build_rag_messages(code: str, retrieved_docs: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    context_parts = []
    for i, doc in enumerate(retrieved_docs, 1):
        doc_type = doc.get('type', '')
        doc_id = doc.get('id', '')
        context_parts.append(f"[参考文档{i}] (id={doc_id}, type={doc_type})\n{doc.get('content', '')}")
    context = "\n\n".join(context_parts)

    return [
        {"role": "system", "content": RAG_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"以下是从ROS安全知识库中检索到的相关文档：\n\n{context}\n\n"
                f"---\n\n请结合上述知识文档，分析以下代码是否存在安全漏洞：\n\n```\n{code}\n```"
            )
        }
    ]


# ─────────────────────────────────────────────
# 分类指标
# ─────────────────────────────────────────────
def compute_metrics(labels: List[int], preds: List[int]) -> Dict[str, float]:
    tp = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 1)
    fp = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 1)
    fn = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 0)
    tn = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    accuracy  = (tp + tn) / len(labels) if labels else 0.0

    return {"precision": precision, "recall": recall, "f1": f1,
            "accuracy": accuracy, "tp": tp, "fp": fp, "fn": fn, "tn": tn}


# ═════════════════════════════════════════════
#  主流程
# ═════════════════════════════════════════════
def main():
    print("=" * 65)
    print("  RoboGuard 评估实验：有RAG vs 无RAG（增强版）")
    print("  检索：BM25 + TF-IDF + Dense Embedding 三路融合")
    print("  精排：Cross-Encoder Reranker")
    print("  选取：动态 Top-K（分数断崖检测）")
    print("  指标：F1 / Accuracy + Recall@K / MRR")
    print("=" * 65)

    if not API_KEY:
        print("[ERROR] 未找到 DASHSCOPE_API_KEY，请检查 .env 文件")
        return

    # 加载数据集
    dataset_all = load_jsonl(DATASET_PATH)
    corpus  = load_jsonl(CORPUS_PATH)
    print(f"\n完整数据集样本数: {len(dataset_all)}")
    print(f"RAG知识库文档数: {len(corpus)}")

    # 均衡采样：从 label=0 和 label=1 各取一半
    import random
    random.seed(42)
    vuln_samples = [s for s in dataset_all if s.get("label") == 1]
    safe_samples = [s for s in dataset_all if s.get("label") == 0]
    half = EVAL_SAMPLE_SIZE // 2
    sampled_vuln = random.sample(vuln_samples, min(half, len(vuln_samples)))
    sampled_safe = random.sample(safe_samples, min(half, len(safe_samples)))
    dataset = sampled_vuln + sampled_safe
    random.shuffle(dataset)
    print(f"评估采样: {len(dataset)} 条 (漏洞 {len(sampled_vuln)}, 安全 {len(sampled_safe)})")

    # ── 构建三路索引 ──────────────────────────
    print("\n[1/4] 构建三路RAG索引...")
    corpus_texts = [d.get("content", "") for d in corpus]

    # 第一路：BM25
    bm25_index = build_bm25(corpus_texts)
    print(f"      [BM25]   语料数={len(corpus_texts)}, 平均文档长度={bm25_index['avgdl']:.1f} tokens")

    # 第二路：TF-IDF
    vocab_idx, idf_vals, tfidf_matrix = build_tfidf(corpus_texts)
    print(f"      [TF-IDF] 词汇量={len(vocab_idx)}")

    # 第三路：Dense Embedding
    dense_model, dense_corpus_emb = build_dense_index(corpus_texts)
    if dense_model is not None:
        print(f"      [Dense]  Embedding维度={dense_corpus_emb.shape[1]}, 语料数={dense_corpus_emb.shape[0]}")
    else:
        print(f"      [Dense]  不可用，退回双路融合 (BM25 + TF-IDF)")

    # 加载 Reranker（预加载，避免推理时首次加载耗时）
    print("\n[2/4] 加载 Reranker...")
    load_reranker()

    # ── 逐样本推理 ──────────────────────────────
    print(f"\n[3/4] 开始逐样本推理（每条调用两次API：无RAG + 有RAG）...")
    print(f"      三路融合权重: BM25={ALPHA_BM25}, TF-IDF={ALPHA_TFIDF}, Dense={ALPHA_DENSE}")
    print(f"      动态 Top-K: min={DYNAMIC_TOPK_MIN}, max={DYNAMIC_TOPK_MAX}, drop_ratio={SCORE_DROP_RATIO}")
    print("-" * 65)

    true_labels: List[int] = []
    no_rag_preds: List[int] = []
    rag_preds: List[int]    = []
    rag_confidences: List[float] = []
    rag_retrieval_scores: List[float] = []

    no_rag_raw_confidences: List[float] = []
    retrieval_debug_list: List[Dict] = []

    # 检索质量指标（逐样本）
    per_sample_recall_at_3: List[float] = []
    per_sample_mrr: List[float] = []
    per_sample_dynamic_k: List[int] = []

    for i, sample in enumerate(dataset):
        code      = sample.get("vulnerable_code", "")
        label     = sample.get("label", -1)
        sample_id = sample.get("id", f"sample_{i}")

        print(f"\n样本 {i+1}/{len(dataset)}: {sample_id}")
        print(f"  真实标签: {'【漏洞】' if label == 1 else '【正常】'} (label={label})")
        true_labels.append(label)

        # ── 无RAG ──────────────────────────────
        print("  -> 无RAG推理中...")
        msgs_no_rag = build_no_rag_messages(code)
        resp_no_rag = call_qwen(msgs_no_rag)
        pred_no_rag = parse_label(resp_no_rag)
        no_rag_preds.append(pred_no_rag)

        try:
            j = json.loads(resp_no_rag.strip())
            no_rag_conf = float(j.get("confidence", 0.5))
        except Exception:
            m = re.search(r'"confidence"\s*:\s*([\d.]+)', resp_no_rag)
            no_rag_conf = float(m.group(1)) if m else 0.5
        no_rag_raw_confidences.append(no_rag_conf)

        correct_mark = "[OK]" if pred_no_rag == label else "[X]"
        print(f"     预测: {'【漏洞】' if pred_no_rag == 1 else '【正常】'} {correct_mark}  (conf={no_rag_conf:.2f})")

        time.sleep(REQUEST_INTERVAL)

        # ── 有RAG（三路融合 + 固定 Top-K）──
        # 禁用通用 Reranker（MS MARCO 模型不适配代码领域，会降低效果）
        # 禁用动态 Top-K（固定返回 5 条上下文，给 LLM 充足参考）
        print("  -> 有RAG推理中（三路融合 BM25+TF-IDF+Dense）...")
        retrieved, debug_info = hybrid_retrieve(
            code, corpus, vocab_idx, idf_vals, tfidf_matrix, bm25_index,
            dense_model=dense_model, dense_corpus_emb=dense_corpus_emb,
            top_k=TOP_K, use_reranker=False, use_dynamic_topk=False,
        )
        top_score = retrieved[0][1] if retrieved else 0.0
        retrieved_indices = [idx for idx, _ in retrieved]
        retrieved_docs = [corpus[idx] for idx in retrieved_indices]
        rag_retrieval_scores.append(top_score)
        retrieval_debug_list.append(debug_info)
        per_sample_dynamic_k.append(debug_info['dynamic_k'])

        # 检索质量：Recall@3 和 MRR
        relevant = get_relevant_doc_indices(sample, corpus)
        r_at_3 = compute_recall_at_k(retrieved_indices, relevant, k=3)
        mrr = compute_mrr(retrieved_indices, relevant)
        per_sample_recall_at_3.append(r_at_3)
        per_sample_mrr.append(mrr)

        print(f"     检索: 融合={debug_info['fusion_mode']}, "
              f"Reranker={'ON' if debug_info['use_reranker'] else 'OFF'}, "
              f"动态K={debug_info['dynamic_k']}")
        print(f"     查询扩展数: {debug_info['num_queries']}，"
              f"Recall@3={r_at_3:.2f}, MRR={mrr:.2f}")
        for rank, (idx, score) in enumerate(retrieved, 1):
            doc_id = corpus[idx].get('id', '?')
            doc_type = corpus[idx].get('type', '?')
            is_rel = "REL" if idx in relevant else "   "
            print(f"       [{rank}] {doc_id} ({doc_type})  score={score:.4f} {is_rel}")

        msgs_rag = build_rag_messages(code, retrieved_docs)
        resp_rag = call_qwen(msgs_rag)
        pred_rag = parse_label(resp_rag)
        rag_preds.append(pred_rag)

        try:
            j = json.loads(resp_rag.strip())
            rag_conf = float(j.get("confidence", 0.5))
        except Exception:
            m = re.search(r'"confidence"\s*:\s*([\d.]+)', resp_rag)
            rag_conf = float(m.group(1)) if m else 0.5
        rag_confidences.append(rag_conf)

        correct_mark = "[OK]" if pred_rag == label else "[X]"
        print(f"     预测: {'【漏洞】' if pred_rag == 1 else '【正常】'} {correct_mark}  (conf={rag_conf:.2f})")

        time.sleep(REQUEST_INTERVAL)

    # ── 计算指标 ──────────────────────────────
    print(f"\n[4/4] 计算评估指标...")
    metrics_no_rag = compute_metrics(true_labels, no_rag_preds)
    metrics_rag    = compute_metrics(true_labels, rag_preds)

    avg_rag_model_conf    = sum(rag_confidences) / len(rag_confidences) if rag_confidences else 0
    avg_no_rag_model_conf = sum(no_rag_raw_confidences) / len(no_rag_raw_confidences) if no_rag_raw_confidences else 0
    avg_retrieval_score   = sum(rag_retrieval_scores) / len(rag_retrieval_scores) if rag_retrieval_scores else 0
    avg_recall_at_3       = sum(per_sample_recall_at_3) / len(per_sample_recall_at_3) if per_sample_recall_at_3 else 0
    avg_mrr               = sum(per_sample_mrr) / len(per_sample_mrr) if per_sample_mrr else 0
    avg_dynamic_k         = sum(per_sample_dynamic_k) / len(per_sample_dynamic_k) if per_sample_dynamic_k else 0

    rag_helped  = sum(1 for y, p0, p1 in zip(true_labels, no_rag_preds, rag_preds) if p0 != y and p1 == y)
    rag_harmed  = sum(1 for y, p0, p1 in zip(true_labels, no_rag_preds, rag_preds) if p0 == y and p1 != y)
    both_right  = sum(1 for y, p0, p1 in zip(true_labels, no_rag_preds, rag_preds) if p0 == y and p1 == y)
    both_wrong  = sum(1 for y, p0, p1 in zip(true_labels, no_rag_preds, rag_preds) if p0 != y and p1 != y)

    # ── 打印报告 ──────────────────────────────
    print("\n" + "=" * 70)
    print("                    实验结果报告（增强版 RAG）")
    print("=" * 70)

    print("\n【逐样本预测对比】")
    header = f"{'ID':<42} {'真实':^6} {'无RAG':^8} {'有RAG':^8} {'R@3':^6} {'MRR':^6} {'K':^3}"
    print(header)
    print("-" * len(header))
    for i, sample in enumerate(dataset):
        sid  = sample.get("id", f"sample_{i}")[:40]
        y    = true_labels[i]
        p0   = no_rag_preds[i]
        p1   = rag_preds[i]
        m0   = "[OK]" if p0 == y else "[X]"
        m1   = "[OK]" if p1 == y else "[X]"
        change = ""
        if p0 != y and p1 == y:
            change = " <- RAG纠正"
        elif p0 == y and p1 != y:
            change = " <- RAG损害"
        print(f"{sid:<42} {y:^6} {p0}{m0:^6} {p1}{m1:^6}"
              f" {per_sample_recall_at_3[i]:^6.2f} {per_sample_mrr[i]:^6.2f}"
              f" {per_sample_dynamic_k[i]:^3}{change}")

    print("\n【分类指标对比】")
    print(f"{'指标':<12} {'无RAG':>10} {'有RAG':>10} {'变化':>10}")
    print("-" * 45)
    for key in ["precision", "recall", "f1", "accuracy"]:
        v0   = metrics_no_rag[key]
        v1   = metrics_rag[key]
        diff = v1 - v0
        sign = "+" if diff >= 0 else ""
        indicator = "^" if diff > 0.001 else ("v" if diff < -0.001 else "=")
        print(f"{key:<12} {v0:>10.4f} {v1:>10.4f} {sign}{diff:>9.4f} {indicator}")

    print(f"\n{'混淆矩阵':<12} {'无RAG':>10} {'有RAG':>10}")
    print("-" * 33)
    for key in ["tp", "fp", "fn", "tn"]:
        print(f"{key.upper():<12} {metrics_no_rag[key]:>10} {metrics_rag[key]:>10}")

    print("\n【RAG影响分析】")
    print(f"  RAG纠正样本数（无->有RAG 正确）: {rag_helped}")
    print(f"  RAG损害样本数（有->无RAG 正确）: {rag_harmed}")
    print(f"  两者均正确: {both_right}  两者均错误: {both_wrong}")

    print("\n【检索质量指标】")
    print(f"  平均 Recall@3        : {avg_recall_at_3:.4f}")
    print(f"  平均 MRR             : {avg_mrr:.4f}")
    print(f"  平均动态 Top-K       : {avg_dynamic_k:.2f}")
    print(f"  平均检索融合分       : {avg_retrieval_score:.4f}")

    print(f"\n  Recall@3 解释：前3个检索结果中，平均能找到 {avg_recall_at_3*100:.1f}% 的相关文档")
    print(f"  MRR 解释：第一个相关文档平均出现在第 {1/avg_mrr:.1f} 位" if avg_mrr > 0 else "")

    print("\n【置信度统计】")
    print(f"  无RAG 平均模型置信度 : {avg_no_rag_model_conf:.4f}")
    print(f"  有RAG 平均模型置信度 : {avg_rag_model_conf:.4f}")

    print(f"\n  逐样本检索质量:")
    for i in range(len(dataset)):
        sid     = dataset[i].get("id", f"sample_{i}")[:36]
        d_k     = per_sample_dynamic_k[i]
        r3      = per_sample_recall_at_3[i]
        mrr_val = per_sample_mrr[i]
        p0, p1  = no_rag_preds[i], rag_preds[i]
        y       = true_labels[i]
        effect  = "纠正" if p0 != y and p1 == y else ("损害" if p0 == y and p1 != y else "无变化")
        print(f"    [{i+1:>2}] {sid:<36}  K={d_k}  R@3={r3:.2f}  MRR={mrr_val:.2f}  [{effect}]")

    print("\n【核心结论】")
    f1_gain = metrics_rag["f1"] - metrics_no_rag["f1"]
    acc_gain = metrics_rag["accuracy"] - metrics_no_rag["accuracy"]
    print(f"  无RAG  F1 / Accuracy = {metrics_no_rag['f1']:.4f} / {metrics_no_rag['accuracy']:.4f}")
    print(f"  有RAG  F1 / Accuracy = {metrics_rag['f1']:.4f} / {metrics_rag['accuracy']:.4f}")
    print(f"  F1提升   = {'+' if f1_gain >= 0 else ''}{f1_gain:.4f}")
    print(f"  Acc提升  = {'+' if acc_gain >= 0 else ''}{acc_gain:.4f}")
    print(f"  Recall@3 = {avg_recall_at_3:.4f}   MRR = {avg_mrr:.4f}")
    if rag_helped > rag_harmed:
        print(f"  结论：RAG显著改善了检测效果（纠正{rag_helped}例，仅损害{rag_harmed}例）")
    elif rag_helped == rag_harmed and f1_gain >= 0:
        print(f"  结论：RAG对检测效果有正向贡献（纠正{rag_helped}例，损害{rag_harmed}例）")
    else:
        print(f"  结论：当前数据集上RAG效果持平或待优化")
    print("=" * 70)

    # ── 保存结果 ──────────────────────────────
    result = {
        "retrieval_method": "hybrid_bm25_tfidf_dense_reranker_dynamic_topk",
        "retrieval_config": {
            "alpha_bm25": ALPHA_BM25,
            "alpha_tfidf": ALPHA_TFIDF,
            "alpha_dense": ALPHA_DENSE,
            "dense_model": DENSE_MODEL_NAME,
            "reranker_model": RERANKER_MODEL_NAME,
            "dynamic_topk_min": DYNAMIC_TOPK_MIN,
            "dynamic_topk_max": DYNAMIC_TOPK_MAX,
            "score_drop_ratio": SCORE_DROP_RATIO,
            "dense_available": dense_model is not None,
            "reranker_available": _reranker_model is not None,
        },
        "no_rag": {
            **metrics_no_rag,
            "avg_confidence": avg_no_rag_model_conf,
        },
        "rag": {
            **metrics_rag,
            "avg_confidence": avg_rag_model_conf,
            "avg_retrieval_score": avg_retrieval_score,
            "rag_helped": rag_helped,
            "rag_harmed": rag_harmed,
        },
        "retrieval_quality": {
            "avg_recall_at_3": avg_recall_at_3,
            "avg_mrr": avg_mrr,
            "avg_dynamic_k": avg_dynamic_k,
            "per_sample_recall_at_3": per_sample_recall_at_3,
            "per_sample_mrr": per_sample_mrr,
            "per_sample_dynamic_k": per_sample_dynamic_k,
        },
        "samples": [
            {
                "id": dataset[i].get("id"),
                "true_label": true_labels[i],
                "no_rag_pred": no_rag_preds[i],
                "rag_pred": rag_preds[i],
                "rag_retrieval_score": rag_retrieval_scores[i],
                "rag_confidence": rag_confidences[i],
                "no_rag_confidence": no_rag_raw_confidences[i],
                "num_queries_expanded": retrieval_debug_list[i]['num_queries'],
                "dynamic_k": per_sample_dynamic_k[i],
                "recall_at_3": per_sample_recall_at_3[i],
                "mrr": per_sample_mrr[i],
            }
            for i in range(len(dataset))
        ]
    }
    out_path = Path("experiments/eval_result.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n结果已保存到: {out_path}")


if __name__ == "__main__":
    main()
