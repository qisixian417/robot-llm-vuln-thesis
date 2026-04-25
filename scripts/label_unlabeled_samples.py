#!/usr/bin/env python3
"""
Label unlabeled vulnerable samples (label=1, cwe_id=None) using qwen-plus LLM.

Usage:
    python scripts/label_unlabeled_samples.py
    python scripts/label_unlabeled_samples.py --resume
"""

import json
import ssl
import time
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional
import argparse
import os
from dotenv import load_dotenv

# Project root
ROOT = Path(__file__).resolve().parent.parent

# SSL workaround for macOS
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# Load environment variables
load_dotenv(ROOT / ".env")

# API configuration
API_KEY = os.getenv("DASHSCOPE_API_KEY")
API_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
MODEL = "qwen-plus"
TEMPERATURE = 0.1

# CWE types
CWE_TYPES = {
    "CWE-119": "缓冲区溢出 (Buffer Overflow)",
    "CWE-78": "命令注入 (OS Command Injection)",
    "CWE-401": "内存泄漏 (Memory Leak)",
    "CWE-476": "空指针解引用 (Null Pointer Dereference)",
    "CWE-362": "竞态条件 (Race Condition)",
    "CWE-416": "Use After Free",
    "CWE-190": "整数溢出 (Integer Overflow)",
    "CWE-134": "格式化字符串 (Format String)"
}

# Confidence threshold
CONFIDENCE_THRESHOLD = 0.6

# Rate limit
RATE_LIMIT_SECONDS = 2


def create_prompt(description: str, code: str) -> str:
    """Create the prompt for LLM classification."""
    return f"""你是机器人代码安全专家。请分析以下代码片段，判断它包含哪种类型的安全漏洞。

代码描述: {description}

代码:
{code}

请从以下8种CWE类型中选择最匹配的一种：
1. CWE-119: 缓冲区溢出 (Buffer Overflow)
2. CWE-78: 命令注入 (OS Command Injection)
3. CWE-401: 内存泄漏 (Memory Leak)
4. CWE-476: 空指针解引用 (Null Pointer Dereference)
5. CWE-362: 竞态条件 (Race Condition)
6. CWE-416: Use After Free
7. CWE-190: 整数溢出 (Integer Overflow)
8. CWE-134: 格式化字符串 (Format String)

请以JSON格式返回（只返回JSON）：
{{"cwe_id": "CWE-XXX", "cwe_name": "名称", "confidence": 0.85, "reasoning": "判断依据"}}"""


def call_qwen_api(prompt: str) -> Optional[Dict]:
    """Call qwen-plus API to classify CWE type."""
    if not API_KEY:
        raise ValueError("DASHSCOPE_API_KEY not found in environment variables")

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "temperature": TEMPERATURE
    }

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        req = urllib.request.Request(
            API_URL,
            data=json.dumps(payload).encode('utf-8'),
            headers=headers,
            method='POST'
        )

        with urllib.request.urlopen(req, context=ssl_ctx, timeout=60) as response:
            result = json.loads(response.read().decode('utf-8'))
            content = result['choices'][0]['message']['content']

            # Parse JSON from response
            # Try to extract JSON if wrapped in markdown code blocks
            if '```json' in content:
                content = content.split('```json')[1].split('```')[0].strip()
            elif '```' in content:
                content = content.split('```')[1].split('```')[0].strip()

            return json.loads(content)

    except Exception as e:
        print(f"API call failed: {e}")
        return None


def load_dataset(file_path: Path) -> List[Dict]:
    """Load dataset from JSONL file."""
    samples = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            samples.append(json.loads(line.strip()))
    return samples


def save_jsonl(samples: List[Dict], file_path: Path):
    """Save samples to JSONL file."""
    with open(file_path, 'w', encoding='utf-8') as f:
        for sample in samples:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')


def load_processed_ids(output_file: Path) -> set:
    """Load IDs of already processed samples."""
    if not output_file.exists():
        return set()

    processed_ids = set()
    with open(output_file, 'r', encoding='utf-8') as f:
        for line in f:
            sample = json.loads(line.strip())
            if sample.get('label') == 1 and sample.get('cwe_id'):
                processed_ids.add(sample['id'])
    return processed_ids


def main():
    parser = argparse.ArgumentParser(description='Label unlabeled vulnerable samples')
    parser.add_argument('--resume', action='store_true', help='Resume from previous run')
    args = parser.parse_args()

    # File paths
    input_file = ROOT / "data" / "dataset_cleaned.jsonl"
    output_file = ROOT / "data" / "dataset_labeled.jsonl"
    low_conf_file = ROOT / "data" / "low_confidence_labels.jsonl"

    print(f"Loading dataset from {input_file}")
    samples = load_dataset(input_file)
    print(f"Loaded {len(samples)} samples")

    # Filter unlabeled vulnerable samples
    unlabeled = [s for s in samples if s.get('label') == 1 and not s.get('cwe_id')]
    print(f"Found {len(unlabeled)} unlabeled vulnerable samples")

    if len(unlabeled) == 0:
        print("No unlabeled samples to process")
        return

    # Load processed IDs if resuming
    processed_ids = set()
    if args.resume:
        processed_ids = load_processed_ids(output_file)
        print(f"Resuming: {len(processed_ids)} samples already processed")
        unlabeled = [s for s in unlabeled if s['id'] not in processed_ids]
        print(f"Remaining: {len(unlabeled)} samples to process")

    # Create sample ID to index mapping
    sample_map = {s['id']: i for i, s in enumerate(samples)}

    # Track low confidence samples
    low_confidence = []

    # Process each unlabeled sample
    total = len(unlabeled)
    for idx, sample in enumerate(unlabeled, 1):
        sample_id = sample['id']
        description = sample.get('description', '')
        code = sample.get('vulnerable_code', '')

        print(f"[{idx}/{total}] Processing {sample_id}...", end=' ')

        # Create prompt and call API
        prompt = create_prompt(description, code)
        result = call_qwen_api(prompt)

        if result:
            cwe_id = result.get('cwe_id', '')
            cwe_name = result.get('cwe_name', '')
            confidence = result.get('confidence', 0.0)
            reasoning = result.get('reasoning', '')

            # Validate CWE ID
            if cwe_id not in CWE_TYPES:
                print(f"Invalid CWE: {cwe_id}")
                continue

            # Update sample in original dataset
            sample_idx = sample_map[sample_id]
            samples[sample_idx]['cwe_id'] = cwe_id
            samples[sample_idx]['cwe_name'] = cwe_name
            samples[sample_idx]['llm_confidence'] = confidence
            samples[sample_idx]['llm_reasoning'] = reasoning

            print(f"cwe={cwe_id} | conf={confidence:.2f}")

            # Track low confidence samples
            if confidence < CONFIDENCE_THRESHOLD:
                low_confidence.append({
                    'id': sample_id,
                    'cwe_id': cwe_id,
                    'cwe_name': cwe_name,
                    'confidence': confidence,
                    'reasoning': reasoning,
                    'description': description,
                    'code': code
                })
        else:
            print("FAILED")

        # Rate limiting
        if idx < total:
            time.sleep(RATE_LIMIT_SECONDS)

    # Save results
    print(f"\nSaving labeled dataset to {output_file}")
    save_jsonl(samples, output_file)

    if low_confidence:
        print(f"Saving {len(low_confidence)} low confidence samples to {low_conf_file}")
        save_jsonl(low_confidence, low_conf_file)

    # Print statistics
    labeled_count = sum(1 for s in samples if s.get('label') == 1 and s.get('cwe_id'))
    print(f"\nStatistics:")
    print(f"  Total samples: {len(samples)}")
    print(f"  Labeled vulnerable samples: {labeled_count}")
    print(f"  Low confidence samples: {len(low_confidence)}")

    # CWE distribution
    cwe_dist = {}
    for s in samples:
        if s.get('label') == 1 and s.get('cwe_id'):
            cwe_id = s['cwe_id']
            cwe_dist[cwe_id] = cwe_dist.get(cwe_id, 0) + 1

    print(f"\nCWE Distribution:")
    for cwe_id in sorted(cwe_dist.keys()):
        print(f"  {cwe_id}: {cwe_dist[cwe_id]}")

    print("\nDone!")


if __name__ == "__main__":
    main()
