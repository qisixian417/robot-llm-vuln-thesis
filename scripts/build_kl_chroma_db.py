# [数据准备] 从rag_knowledge_v1.jsonl构建KL-RAG Chroma向量库，使用与code-level独立的collection（roboguard_kl_rag）
#!/usr/bin/env python3
"""Build Chroma vector DB for Knowledge-Level RAG.

Reads data/rag_knowledge_v1.jsonl (output of build_knowledge_base.py)
and creates a separate Chroma collection (kl_rag) without affecting
the original code-level collection.

Usage:
    python scripts/build_kl_chroma_db.py --reset
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from rag.knowledge_retriever import (
    DEFAULT_KL_COLLECTION_NAME,
    DEFAULT_KL_PERSIST_DIR,
    KnowledgeRAGRetriever,
    knowledge_to_documents,
)


def load_jsonl(path: Path) -> List[dict]:
    items = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=str, default="data/rag_knowledge_v1.jsonl")
    parser.add_argument("--persist-dir", type=str, default=DEFAULT_KL_PERSIST_DIR)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()

    input_path = ROOT / args.input
    if not input_path.exists():
        print(f"ERROR: {input_path} not found")
        print("Run scripts/build_knowledge_base.py first.")
        return

    items = load_jsonl(input_path)
    print(f"Loaded {len(items)} knowledge entries from {input_path}")

    persist_dir = ROOT / args.persist_dir if not Path(args.persist_dir).is_absolute() else Path(args.persist_dir)

    # Need an LLM to instantiate the retriever, but build process doesn't use it
    # Just instantiate vectorstore directly
    from rag.knowledge_retriever import (
        Chroma, OpenAIEmbeddings,
    )
    import os

    embeddings = OpenAIEmbeddings(
        model=os.getenv("EMBEDDING_MODEL", "text-embedding-v2"),
        openai_api_key=os.getenv("DASHSCOPE_API_KEY"),
        openai_api_base=os.getenv(
            "EMBEDDING_BASE_URL",
            "https://dashscope.aliyuncs.com/compatible-mode/v1",
        ),
        check_embedding_ctx_length=False,
        chunk_size=10,  # text-embedding-v3 max batch = 10
    )
    vectorstore = Chroma(
        collection_name=DEFAULT_KL_COLLECTION_NAME,
        persist_directory=str(persist_dir),
        embedding_function=embeddings,
    )

    if args.reset:
        print("Resetting KL collection...")
        try:
            vectorstore.delete_collection()
        except Exception as e:
            print(f"  (delete failed: {e})")
        vectorstore = Chroma(
            collection_name=DEFAULT_KL_COLLECTION_NAME,
            persist_directory=str(persist_dir),
            embedding_function=embeddings,
        )

    documents = knowledge_to_documents(items)
    print(f"Building Chroma index with {len(documents)} documents (batch={args.batch_size})...")
    total = len(documents)
    for start in range(0, total, args.batch_size):
        batch = documents[start:start + args.batch_size]
        vectorstore.add_documents(batch)
        end = min(start + args.batch_size, total)
        print(f"  Indexed {end}/{total}")

    persist = getattr(vectorstore, "persist", None)
    if callable(persist):
        try:
            persist()
        except Exception:
            pass

    print(f"\nDone. Collection: {DEFAULT_KL_COLLECTION_NAME}")
    print(f"Persist dir: {persist_dir}")
    print(f"Total documents: {vectorstore._collection.count()}")


if __name__ == "__main__":
    main()
