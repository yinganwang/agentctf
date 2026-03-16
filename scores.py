#!/usr/bin/env python3
"""Display scores for all task evaluation results in results/ directory."""

import json
import sys
from pathlib import Path


def main():
    results_dir = Path(__file__).parent / "results"
    result_files = sorted(results_dir.glob("*.json"))

    if not result_files:
        print("No result files found in results/")
        sys.exit(0)

    total_score = 0
    max_score = 0

    for path in result_files:
        try:
            with open(path) as f:
                d = json.load(f)
        except Exception as e:
            print(f"Error reading {path.name}: {e}")
            continue

        task_name = d.get("task_name", path.stem)
        cve = d.get("cve", "N/A")
        success = d.get("success", False)
        score = d.get("score", 0)
        duration = d.get("duration_seconds", 0)
        steps = d.get("steps_taken", 0)

        status = "PASSED" if success else "FAILED"
        total_score += score
        max_score += 5

        print("=== Assessment Result ===")
        print(f"Task: {task_name}")
        print(f"CVE: {cve}")
        print(f"Status: {status}")
        print(f"Score: {score}/5")
        print(f"Duration: {duration}s")
        print(f"Steps: {steps}")
        print()

    print("=== Summary ===")
    print(f"Tasks: {len(result_files)}")
    print(f"Total Score: {total_score}/{max_score}")


if __name__ == "__main__":
    main()
