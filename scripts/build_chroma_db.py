"""从 JSONL 语料构建 Chroma 向量数据库。"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from dotenv import load_dotenv
from langchain_core.documents import Document

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rag.retriever import DEFAULT_PERSIST_DIR, RAGRetriever


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            items.append(json.loads(line))
    return items


def to_documents(items: List[Dict[str, Any]]) -> List[Document]:
    documents: List[Document] = []
    for item in items:
        metadata = {"id": item.get("id"), "type": item.get("type")}
        extra_metadata = item.get("metadata", {})
        if isinstance(extra_metadata, dict):
            metadata.update(extra_metadata)

        content = item.get("content", "")
        if not isinstance(content, str):
            content = json.dumps(content, ensure_ascii=False)

        documents.append(
            Document(
                page_content=content,
                metadata=metadata,
            )
        )
    return documents


def add_in_batches(retriever: RAGRetriever, documents: List[Document], batch_size: int) -> None:
    total = len(documents)
    for start in range(0, total, batch_size):
        batch = documents[start : start + batch_size]
        retriever.add_documents(batch)
        end = min(start + batch_size, total)
        print(f"已写入 {end}/{total} 条文档")


def main() -> None:
    load_dotenv(ROOT / ".env")

    parser = argparse.ArgumentParser(description="Build Chroma vector database for RoboGuard")
    parser.add_argument(
        "--corpus",
        type=str,
        default="data/rag_corpus_full.jsonl",
        help="RAG语料 JSONL 路径",
    )
    parser.add_argument(
        "--persist-dir",
        type=str,
        default=DEFAULT_PERSIST_DIR,
        help="Chroma 持久化目录",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=64,
        help="每批写入的文档数",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="写入前清空已有集合",
    )
    args = parser.parse_args()

    corpus_path = ROOT / args.corpus if not Path(args.corpus).is_absolute() else Path(args.corpus)
    if not corpus_path.exists():
        raise FileNotFoundError(f"未找到语料文件: {corpus_path}")

    items = load_jsonl(corpus_path)
    if not items:
        raise RuntimeError(f"语料为空: {corpus_path}")

    persist_dir = ROOT / args.persist_dir if not Path(args.persist_dir).is_absolute() else Path(args.persist_dir)
    retriever = RAGRetriever(persist_dir=str(persist_dir))
    if args.reset:
        print("检测到 --reset，正在清空旧集合...")
        retriever.reset()

    documents = to_documents(items)
    print(f"开始构建 Chroma 向量数据库，语料条数: {len(documents)}")
    add_in_batches(retriever, documents, max(args.batch_size, 1))
    print(f"构建完成，当前集合文档数: {retriever.count()}")
    print(f"持久化目录: {persist_dir}")


if __name__ == "__main__":
    main()
