#!/usr/bin/env python3
"""AST Studio Benchmark Script.

Measures precise execution times across representative Python samples for:
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

SAMPLES = [
    (
        "Small Function (5 lines)",
        '''def calculate_metrics(values, factor=1.5):
    """Compute normalized scaling factor across array."""
    total = sum(values)
    scaled = [v * factor for v in values if v > 0]
    return total, scaled
''',
    ),
    (
        "Medium Module (16 lines)",
        '''def process_transactions(records: list[dict], threshold: float = 100.0) -> list[dict]:
    flagged = []
    for tx in records:
        amount = tx.get("amount", 0.0)
        user = tx.get("user_id")
        if amount > threshold and user:
            risk = "HIGH" if amount > threshold * 5 else "MEDIUM"
            flagged.append({"tx_id": tx.get("id"), "risk": risk})
        elif amount <= 0:
            continue
    return flagged
''',
    ),
    (
        "Multi-Method Class (24 lines)",
        '''class DataPipeline:
    def __init__(self, name: str, batch_size: int = 64):
        self.name = name
        self.batch_size = batch_size
        self._processed = 0

    def ingest(self, raw_items: list) -> list:
        cleaned = [item for item in raw_items if item is not None]
        self._processed += len(cleaned)
        return cleaned

    def execute(self, items: list) -> dict:
        data = self.ingest(items)
        if not data:
            return {"status": "empty", "count": 0}
        total = sum(data)
        return {"status": "success", "count": len(data), "total": total}
''',
    ),
]


def benchmark_snippet(snippet: str, iterations: int = 50) -> dict[str, float]:
    # Warmup
    warm_analysis = analyze_code(snippet)
    simulate_attacks(snippet)
    generate_commented_code(snippet, warm_analysis)

    # 1. AST Analysis
    t0 = time.perf_counter()
    for _ in range(iterations):
        analysis = analyze_code(snippet)
    t1 = time.perf_counter()
    ast_time_ms = ((t1 - t0) / iterations) * 1000

    # 2. Security Probing
    t0 = time.perf_counter()
    for _ in range(iterations):
        simulate_attacks(snippet)
    t1 = time.perf_counter()
    security_time_ms = ((t1 - t0) / iterations) * 1000

    # 3. Comment Generation
    t0 = time.perf_counter()
    for _ in range(iterations):
        generate_commented_code(snippet, analysis)
    t1 = time.perf_counter()
    comment_time_ms = ((t1 - t0) / iterations) * 1000

    # 4. Total Pipeline
    t0 = time.perf_counter()
    for _ in range(iterations):
        a = analyze_code(snippet)
        simulate_attacks(snippet)
        generate_commented_code(snippet, a)
    t1 = time.perf_counter()
    pipeline_time_ms = ((t1 - t0) / iterations) * 1000

    return {
        "ast_analysis_ms": round(ast_time_ms, 2),
        "security_probing_ms": round(security_time_ms, 2),
        "comment_generation_ms": round(comment_time_ms, 2),
        "total_pipeline_ms": round(pipeline_time_ms, 2),
    }


def run_benchmark(iterations: int = 50) -> dict[str, any]:
    sample_results = {}
    totals = {
        "ast_analysis_ms": 0.0,
        "security_probing_ms": 0.0,
        "comment_generation_ms": 0.0,
        "total_pipeline_ms": 0.0,
    }
    for name, code in SAMPLES:
        res = benchmark_snippet(code, iterations=iterations)
        sample_results[name] = res
        for k in totals:
            totals[k] += res[k]

    n = len(SAMPLES)
    averaged = {k: round(v / n, 2) for k, v in totals.items()}
    return {
        "iterations": iterations,
        "samples": sample_results,
        "averaged": averaged,
    }


if __name__ == "__main__":
    iterations = 50
    results = run_benchmark(iterations)
    print("=" * 64)
    print(" AST Studio Deterministic Static Analysis Benchmark")
    print(f" Evaluation across {len(SAMPLES)} representative Python samples ({iterations} iterations each)")
    print("=" * 64)
    for sample_name, res in results["samples"].items():
        print(f"\n--- {sample_name} ---")
        print(f"  AST Parsing & Metrics:        {res['ast_analysis_ms']:>6.2f} ms")
        print(f"  Security AST Pattern Scan:    {res['security_probing_ms']:>6.2f} ms")
        print(f"  AST Docstring & Comments:     {res['comment_generation_ms']:>6.2f} ms")
        print(f"  Full Static Pipeline:         {res['total_pipeline_ms']:>6.2f} ms")

    avg = results["averaged"]
    print("\n" + "=" * 64)
    print(" OVERALL MEAN LATENCY & THROUGHPUT")
    print("=" * 64)
    print(f" AST Parsing & Metrics:        {avg['ast_analysis_ms']:>6.2f} ms (~{int(1000 / max(0.1, avg['ast_analysis_ms']))} files/sec)")
    print(f" Security AST Pattern Scan:    {avg['security_probing_ms']:>6.2f} ms (~{int(1000 / max(0.1, avg['security_probing_ms']))} files/sec)")
    print(f" AST Docstring & Comments:     {avg['comment_generation_ms']:>6.2f} ms (~{int(1000 / max(0.1, avg['comment_generation_ms']))} files/sec)")
    print("-" * 64)
    print(f" Full Static Pipeline:         {avg['total_pipeline_ms']:>6.2f} ms (~{int(1000 / max(0.1, avg['total_pipeline_ms']))} files/sec)")
    print("=" * 64)
