#!/usr/bin/env python3
"""
Merge labeled dataset + expanded samples, add metadata, split train/test, build RAG corpus.
"""

import json
import hashlib
import random
from pathlib import Path
from collections import Counter, defaultdict

# Set random seed for reproducibility
random.seed(42)

# Project root
ROOT = Path(__file__).resolve().parent.parent

# Component mapping
COMPONENT_MAP = {
    # Core Middleware
    "ros2/rclcpp": "core_middleware", "ros2/rcl": "core_middleware",
    "ros2/rclpy": "core_middleware", "ros2/rcutils": "core_middleware",
    "ros2/rmw": "core_middleware", "ros2/rosidl": "core_middleware",
    "ros/ros_comm": "core_middleware", "ros/ros": "core_middleware",
    "eProsima/Fast-DDS": "core_middleware", "ros2/launch": "core_middleware",
    # Application
    "ros-planning/navigation": "application", "ros-planning/navigation2": "application",
    "ros-planning/moveit2": "application", "moveit/moveit": "application",
    "ros-controls/ros2_control": "application", "SteveMacenski/slam_toolbox": "application",
    "ros/actionlib": "application", "ros2/geometry2": "application",
    "RobotWebTools/rosbridge_suite": "application",
    # Simulation
    "gazebosim/gz-sim": "simulation", "gazebosim/gz-transport": "simulation",
    "gazebosim/gz-physics": "simulation", "gazebosim/gz-rendering": "simulation",
    "gazebosim/gz-sensors": "simulation", "osrf/gazebo": "simulation",
    "carla-simulator/carla": "simulation",
    # Autonomous Driving
    "ApolloAuto/apollo": "autonomous_driving", "autowarefoundation/autoware": "autonomous_driving",
    "autowarefoundation/autoware.universe": "autonomous_driving", "commaai/openpilot": "autonomous_driving",
    # Drone
    "PX4/PX4-Autopilot": "drone", "ArduPilot/ardupilot": "drone",
    "mavlink/mavros": "drone",
    # Perception
    "ros-perception/image_common": "perception", "ros-perception/image_pipeline": "perception",
    "ros-perception/perception_pcl": "perception", "ros-perception/vision_opencv": "perception",
    # Embedded/Micro
    "micro-ROS/micro_ros_setup": "embedded",
}


def classify_component(repo: str) -> str:
    """Classify ROS component based on repo name."""
    return COMPONENT_MAP.get(repo, "other")


def classify_ros_version(repo: str) -> str:
    """Classify ROS version based on repo name."""
    repo_lower = repo.lower()

    if repo.startswith("ros2/") or "ros2" in repo_lower:
        return "ROS2"
    elif repo.startswith("ros/"):
        return "ROS1"
    elif repo.startswith("gazebosim/"):
        return "ROS2"
    elif repo == "osrf/gazebo":
        return "ROS1"
    else:
        return "other"


def create_hash(repo: str, code: str) -> str:
    """Create hash from repo + first 200 chars of code."""
    content = f"{repo}:{code[:200]}"
    return hashlib.md5(content.encode()).hexdigest()


def load_jsonl(filepath: Path) -> list:
    """Load JSONL file."""
    samples = []
    if not filepath.exists():
        print(f"Warning: {filepath} not found, skipping...")
        return samples

    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def save_jsonl(samples: list, filepath: Path):
    """Save samples to JSONL file."""
    with open(filepath, 'w', encoding='utf-8') as f:
        for sample in samples:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
    print(f"✓ Saved {len(samples)} samples to {filepath}")


def stratified_split(samples: list, test_ratio: float = 0.25) -> tuple:
    """Stratified split by CWE ID."""
    # Group by CWE
    cwe_groups = defaultdict(list)
    for sample in samples:
        cwe = sample.get('cwe_id', 'unknown')
        cwe_groups[cwe].append(sample)

    train_set = []
    test_set = []

    for cwe, group in cwe_groups.items():
        random.shuffle(group)
        split_idx = int(len(group) * (1 - test_ratio))
        train_set.extend(group[:split_idx])
        test_set.extend(group[split_idx:])

    return train_set, test_set


def print_statistics(samples: list, train: list, test: list, rag: list):
    """Print comprehensive statistics."""
    print("\n" + "="*80)
    print("DATASET STATISTICS")
    print("="*80)

    # Total samples
    print(f"\nTotal samples: {len(samples)}")
    vuln_count = sum(1 for s in samples if s.get('label') == 1)
    print(f"  Vulnerable: {vuln_count} ({vuln_count/len(samples)*100:.1f}%)")
    print(f"  Clean: {len(samples) - vuln_count} ({(len(samples)-vuln_count)/len(samples)*100:.1f}%)")

    # Per-CWE distribution
    print("\nPer-CWE distribution:")
    cwe_counter = Counter(s.get('cwe_id') or 'none' for s in samples if s.get('label') == 1)
    for cwe, count in sorted(cwe_counter.items(), key=lambda x: (x[0] is None, x[0])):
        print(f"  {cwe}: {count}")

    # Per-component distribution
    print("\nPer-component distribution:")
    comp_counter = Counter(s.get('ros_component', 'unknown') for s in samples)
    for comp, count in sorted(comp_counter.items(), key=lambda x: -x[1]):
        print(f"  {comp}: {count}")

    # Per-language distribution
    print("\nPer-language distribution:")
    lang_counter = Counter(s.get('language', 'unknown') for s in samples)
    for lang, count in sorted(lang_counter.items(), key=lambda x: -x[1]):
        print(f"  {lang}: {count}")

    # ROS version distribution
    print("\nROS version distribution:")
    ros_counter = Counter(s.get('ros_version', 'unknown') for s in samples)
    for version, count in sorted(ros_counter.items(), key=lambda x: -x[1]):
        print(f"  {version}: {count}")

    # Train/test split
    print("\nTrain/Test split:")
    print(f"  Training set: {len(train)} samples")
    train_vuln = sum(1 for s in train if s.get('label') == 1)
    print(f"    Vulnerable: {train_vuln} ({train_vuln/len(train)*100:.1f}%)")
    print(f"  Test set: {len(test)} samples")
    test_vuln = sum(1 for s in test if s.get('label') == 1)
    print(f"    Vulnerable: {test_vuln} ({test_vuln/len(test)*100:.1f}%)")

    # RAG corpus
    print(f"\nRAG corpus: {len(rag)} vulnerable samples (from training set only)")

    # Overlap check
    test_ids = set(s.get('id', '') for s in test)
    rag_ids = set(s.get('id', '') for s in rag)
    overlap = test_ids & rag_ids
    overlap_pct = len(overlap) / len(test_ids) * 100 if test_ids else 0
    print(f"\nOverlap check:")
    print(f"  Test set IDs: {len(test_ids)}")
    print(f"  RAG corpus IDs: {len(rag_ids)}")
    print(f"  Overlap: {len(overlap)} ({overlap_pct:.1f}%)")
    if overlap_pct == 0:
        print("  ✓ No data leakage detected!")
    else:
        print("  ⚠ WARNING: Data leakage detected!")

    print("="*80 + "\n")


def main():
    print("Starting dataset merge and split process...")

    # Load datasets
    print("\n1. Loading datasets...")
    labeled_path = ROOT / "data" / "dataset_labeled.jsonl"
    expanded_path = ROOT / "data" / "github_expanded_samples.jsonl"

    labeled_samples = load_jsonl(labeled_path)
    expanded_samples = load_jsonl(expanded_path)

    print(f"  Loaded {len(labeled_samples)} labeled samples")
    print(f"  Loaded {len(expanded_samples)} expanded samples")

    # Merge
    print("\n2. Merging samples...")
    all_samples = labeled_samples + expanded_samples
    print(f"  Total before deduplication: {len(all_samples)}")

    # Deduplicate
    print("\n3. Deduplicating by hash(repo + code[:200])...")
    seen_hashes = set()
    unique_samples = []

    for sample in all_samples:
        repo = sample.get('repo', '')
        code = sample.get('vulnerable_code', '')
        sample_hash = create_hash(repo, code)

        if sample_hash not in seen_hashes:
            seen_hashes.add(sample_hash)
            unique_samples.append(sample)

    duplicates_removed = len(all_samples) - len(unique_samples)
    print(f"  Removed {duplicates_removed} duplicates")
    print(f"  Unique samples: {len(unique_samples)}")

    # Add metadata
    print("\n4. Adding metadata fields...")
    for i, sample in enumerate(unique_samples):
        # Add ID if not present
        if 'id' not in sample:
            sample['id'] = f"sample_{i+1:04d}"

        # Add ros_component
        repo = sample.get('repo', '')
        sample['ros_component'] = classify_component(repo)

        # Add ros_version
        sample['ros_version'] = classify_ros_version(repo)

    print(f"  Added metadata to {len(unique_samples)} samples")

    # Stratified split
    print("\n5. Performing stratified split (75/25 by CWE)...")
    train_samples, test_samples = stratified_split(unique_samples, test_ratio=0.25)
    print(f"  Training set: {len(train_samples)} samples")
    print(f"  Test set: {len(test_samples)} samples")

    # Build RAG corpus (only vulnerable samples from training set)
    print("\n6. Building RAG corpus (vulnerable samples from training set only)...")
    rag_corpus = [s for s in train_samples if s.get('label') == 1]
    print(f"  RAG corpus: {len(rag_corpus)} samples")

    # Save outputs
    print("\n7. Saving outputs...")
    output_dir = ROOT / "data"
    output_dir.mkdir(exist_ok=True)

    save_jsonl(unique_samples, output_dir / "dataset_final_v2.jsonl")
    save_jsonl(train_samples, output_dir / "train_v2.jsonl")
    save_jsonl(test_samples, output_dir / "test_v2.jsonl")
    save_jsonl(rag_corpus, output_dir / "rag_corpus_v2.jsonl")

    # Print statistics
    print_statistics(unique_samples, train_samples, test_samples, rag_corpus)

    print("✓ Dataset merge and split completed successfully!")


if __name__ == "__main__":
    main()
