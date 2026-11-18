#!/usr/bin/env python3
"""AST Studio Benchmark Script.

Measures precise execution times for:
1. Pure AST Parsing & Symbol Resolution
2. Security Vulnerability AST Probing
3. Deterministic Comment & Docstring Generation
4. Full End-to-End Static Pipeline
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

# Ensure root is on path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

# Force AST deterministic mode for benchmark repeatability
os.environ["AI_PROVIDER"] = "ast"

from backend.ast_analyzer import analyze_code
from backend.code_analysis import generate_commented_code
from backend.security_attack_agent import simulate_attacks

BENCHMARK_SNIPPET = '''def calculate_metrics(values, factor=1.5):
    """Compute normalized scaling factor across array."""
    total = sum(values)
    scaled = [v * factor for v in values if v > 0]
    return total, scaled
'''


def run_benchmark(iterations: int = 50) -> dict[str, float]:
    # Warmup
    warm_analysis = analyze_code(BENCHMARK_SNIPPET)
    simulate_attacks(BENCHMARK_SNIPPET)
    generate_commented_code(BENCHMARK_SNIPPET, warm_analysis)

    # 1. AST Analysis
    t0 = time.perf_counter()
    for _ in range(iterations):
        analysis = analyze_code(BENCHMARK_SNIPPET)
    t1 = time.perf_counter()
    ast_time_ms = ((t1 - t0) / iterations) * 1000

    # 2. Security Probing
    t0 = time.perf_counter()
    for _ in range(iterations):
        simulate_attacks(BENCHMARK_SNIPPET)
    t1 = time.perf_counter()
    security_time_ms = ((t1 - t0) / iterations) * 1000

    # 3. Comment Generation
    t0 = time.perf_counter()
    for _ in range(iterations):
        generate_commented_code(BENCHMARK_SNIPPET, analysis)
    t1 = time.perf_counter()
    comment_time_ms = ((t1 - t0) / iterations) * 1000

    # 4. Total Pipeline
    t0 = time.perf_counter()
    for _ in range(iterations):
        a = analyze_code(BENCHMARK_SNIPPET)
        simulate_attacks(BENCHMARK_SNIPPET)
        generate_commented_code(BENCHMARK_SNIPPET, a)
    t1 = time.perf_counter()
    pipeline_time_ms = ((t1 - t0) / iterations) * 1000

    return {
        "ast_analysis_ms": round(ast_time_ms, 2),
        "security_probing_ms": round(security_time_ms, 2),
        "comment_generation_ms": round(comment_time_ms, 2),
        "total_pipeline_ms": round(pipeline_time_ms, 2),
    }


if __name__ == "__main__":
    iterations = 50
    results = run_benchmark(iterations)
    print("=" * 60)
    print(" AST Studio Deterministic Static Analysis Benchmark")
    print(f" Sample: {len(BENCHMARK_SNIPPET.splitlines())} lines | Iterations: {iterations}")
    print("=" * 60)
    print(f" AST Parsing & Metrics:        {results['ast_analysis_ms']} ms")
    print(f" Security AST Pattern Scan:    {results['security_probing_ms']} ms")
    print(f" AST Docstring & Comments:     {results['comment_generation_ms']} ms")
    print("-" * 60)
    print(f" Full Static Pipeline:         {results['total_pipeline_ms']} ms")
    print("=" * 60)
