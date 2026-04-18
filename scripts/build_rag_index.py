"""
RAG索引构建脚本
构建向量索引 + BM25索引
"""
import argparse
import json
import pickle
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import yaml


def load_config(config_path: str) -> Dict[str, Any]:
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    items = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            items.append(json.loads(line))
    return items


def load_corpus(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    docs: List[Dict[str, Any]] = []
    for source in config.get("corpus_sources", []):
        p = Path(source["path"])
        if not p.exists():
            print(f"跳过不存在语料: {p}")
            continue
        chunk = load_jsonl(p)
        docs.extend(chunk)
        print(f"加载语料 {p}: {len(chunk)} 条")
    return docs


def build_embeddings(texts: List[str], model_name: str, dim: int) -> np.ndarray:
    try:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer(model_name)
        emb = model.encode(texts, show_progress_bar=True, batch_size=32, normalize_embeddings=True)
        return np.asarray(emb, dtype=np.float32)
    except Exception as e:
        print(f"embedding模型不可用，退回随机向量: {e}")
        # 保证流程可跑通
        rng = np.random.default_rng(42)
        emb = rng.standard_normal((len(texts), dim), dtype=np.float32)
        # 归一化
        norms = np.linalg.norm(emb, axis=1, keepdims=True) + 1e-8
        return emb / norms


def build_bm25(docs: List[Dict[str, Any]]):
    try:
        from rank_bm25 import BM25Okapi
    except Exception as e:
        print(f"BM25模块不可用，跳过: {e}")
        return None

    tokenized = []
    for d in docs:
        t = d.get("content", "")
        tokenized.append(t.lower().split())
    return BM25Okapi(tokenized)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()

    config = load_config(args.config)
    docs = load_corpus(config)
    if not docs:
        print("语料为空，先运行 prepare_rag_corpus.py")
        return

    texts = [d.get("content", "")[:2000] for d in docs]

    emb_model = config["vector_store"].get("embedding_model", "sentence-transformers/all-MiniLM-L6-v2")
    dim = int(config["vector_store"].get("dimension", 768))
    embeddings = build_embeddings(texts, emb_model, dim)

    bm25 = build_bm25(docs)

    index_path = Path(config["vector_store"]["index_path"])
    index_path.mkdir(parents=True, exist_ok=True)

    with open(index_path / "corpus.json", "w", encoding="utf-8") as f:
        json.dump(docs, f, ensure_ascii=False, indent=2)

    np.save(str(index_path / "embeddings.npy"), embeddings)

    if bm25 is not None:
        with open(index_path / "bm25.pkl", "wb") as f:
            pickle.dump(bm25, f)

    metadata = {
        "corpus_size": len(docs),
        "embedding_model": emb_model,
        "embedding_dim": int(embeddings.shape[1]),
        "has_bm25": bm25 is not None
    }
    with open(index_path / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)

    print("RAG索引构建完成")
    print(f"index_path={index_path}")
    print(f"corpus_size={len(docs)}")


if __name__ == "__main__":
    main()
