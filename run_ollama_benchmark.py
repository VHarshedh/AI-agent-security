"""
run_ollama_benchmark.py — Multi-Attack Ollama Gemma-4 Benchmark Runner
======================================================================
Runs attack_v35, attack_v36, attack_v37, and attack_v38 against the local
Ollama Gemma-4 agent and prints comparative performance metrics and projected
Kaggle scores.

Usage:
    python run_ollama_benchmark.py [--budget SECONDS] [--max-score-cands N] [--files F1 F2 ...]

Examples:
    python run_ollama_benchmark.py --budget 60 --max-score-cands 10    # Quick 1-min smoke test
    python run_ollama_benchmark.py --budget 900                         # Full 15-min benchmark
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from pathlib import Path
from typing import Any

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── Import SDK components ───────────────────────────────────────────────────
EXTRACT_DIR = Path("_sdk_extracted")
if EXTRACT_DIR.exists():
    sys.path.insert(0, str(EXTRACT_DIR))

try:
    from aicomp_sdk.attacks import AttackAlgorithmBase, AttackCandidate, AttackRunConfig
    from aicomp_sdk.core.cells import cell_signature
    from aicomp_sdk.core.env.sandbox import SandboxEnv
    from aicomp_sdk.core.predicates import eval_predicates
    from aicomp_sdk.guardrails.optimal import Guardrail
    from aicomp_sdk.scoring import score_attack, score_attack_raw
except ImportError:
    print("❌ Failed to load aicomp_sdk. Ensure _sdk_extracted is present.")
    traceback.print_exc()
    sys.exit(1)

# Import OllamaAgent from ollama_test
from ollama_test import FIXTURES_DIR, OllamaAgent, load_attack_algorithm

DEFAULT_FILES = [
    "attack_v35_dual_turn_pipeline.py",
    "attack_v36_adaptive_turn_ladder.py",
    "attack_v37_gpt_boost_multiturn.py",
    "attack_v38_elite_turn_apex.py",
]

KAGGLE_FULL_BUDGET_S = 8750.0


def benchmark_single_attack(
    attack_file: str,
    budget_s: float,
    max_score_cands: int | None = None,
    verbose_ollama: bool = False,
) -> dict[str, Any]:
    """Runs a single attack against Ollama Gemma-4 and evaluates score."""
    print("\n" + "═" * 70)
    print(f"🚀 Benchmarking: {attack_file}")
    print(f"⏱️  Budget: {budget_s}s | Target: Ollama Gemma-4")
    print("═" * 70)

    attack_path = Path(attack_file)
    if not attack_path.exists():
        print(f"❌ Error: File not found: {attack_file}")
        return {"file": attack_file, "error": "File not found"}

    try:
        AttackClass = load_attack_algorithm(str(attack_path))
    except Exception as e:
        print(f"❌ Error loading {attack_file}: {e}")
        return {"file": attack_file, "error": f"Import error: {e}"}

    # 1. Initialize Ollama Sandbox
    agent = OllamaAgent(verbose=verbose_ollama)
    env = SandboxEnv(
        seed=42,
        fixtures_dir=FIXTURES_DIR,
        agent=agent,
        guardrail=Guardrail(),
        max_tool_hops=8,
    )

    algo = AttackClass()
    cfg = AttackRunConfig(time_budget_s=budget_s)

    # 2. Run Attack Fill
    print(f"\n▶ Running attack generation (fill) for {budget_s}s...")
    t_start = time.time()
    try:
        candidates = algo.run(env, cfg)
    except Exception as e:
        print(f"❌ Exception during attack run: {e}")
        traceback.print_exc()
        candidates = []
    fill_elapsed = time.time() - t_start

    cand_count = len(candidates)
    print(f"✅ Attack generation complete: {cand_count} candidates produced in {fill_elapsed:.1f}s")

    if not candidates:
        return {
            "file": attack_file,
            "candidates_count": 0,
            "fill_time": fill_elapsed,
            "raw_score": 0.0,
            "norm_score": 0.0,
            "projected_kaggle": 0.0,
        }

    # 3. Replay Evaluation (scoring)
    eval_list = candidates[:max_score_cands] if (max_score_cands and max_score_cands > 0) else candidates
    print(f"\n▶ Evaluating {len(eval_list)}/{cand_count} candidates on Gemma-4...")

    findings = []
    hits = 0
    t_eval = time.time()
    for idx, cand in enumerate(eval_list, 1):
        env.reset()
        msgs = list(getattr(cand, "user_messages", getattr(cand, "prompts", [])))
        for m in msgs:
            env.interact(m)
        trace = env.export_trace_dict()
        preds = eval_predicates(trace)
        c_sig = cell_signature(
            trace.get("tool_events", []),
            egress_data=trace.get("egress", []),
            user_messages=trace.get("user_messages", []),
        )
        findings.append({"predicates": preds, "cell_signature": c_sig})
        hits += len(preds)

        if idx % 5 == 0 or idx == len(eval_list):
            el = time.time() - t_eval
            print(f"   ... evaluated {idx}/{len(eval_list)} ({el:.1f}s, hits={hits})", flush=True)

    raw_eval = score_attack_raw(findings)
    norm_eval = score_attack(findings)

    # Extrapolate to full candidate set if subset evaluated
    ratio = cand_count / len(eval_list)
    raw_full = raw_eval * ratio
    norm_full = norm_eval * ratio

    # Projected Gemma-4 full Kaggle score (scaled from budget_s to 8750s)
    time_scale = (KAGGLE_FULL_BUDGET_S / budget_s) if budget_s > 0 else 1.0
    projected_gemma_norm = min(1000.0, norm_full * time_scale)

    print(f"\n📊 Results for {attack_file}:")
    print(f"   • Candidates: {cand_count}")
    print(f"   • Predicates Hit: {hits * ratio:.0f}")
    print(f"   • 15-Min Raw Score: {raw_full:.2f}")
    print(f"   • 15-Min Gemma-4 Norm: {norm_full:.4f}")
    print(f"   • Projected Full Kaggle Gemma-4 Score (8750s): ~{projected_gemma_norm:.2f}")

    return {
        "file": attack_file,
        "candidates_count": cand_count,
        "fill_time": fill_elapsed,
        "raw_score": raw_full,
        "norm_score": norm_full,
        "projected_gemma_full": projected_gemma_norm,
    }


def main():
    parser = argparse.ArgumentParser(description="Run Gemma-4 Ollama benchmark on attack algorithms.")
    parser.add_argument("--budget", type=int, default=900, help="Time budget in seconds per attack (default: 900 for 15 mins)")
    parser.add_argument("--max-score-cands", type=int, default=15, help="Max candidates to replay for score validation (default: 15)")
    parser.add_argument("--verbose-ollama", action="store_true", help="Print per-hop Ollama interaction details")
    parser.add_argument("--files", nargs="*", default=DEFAULT_FILES, help="List of attack files to benchmark")
    args = parser.parse_args()

    print("=" * 75)
    print("🎯 OLLAMA GEMMA-4 MULTI-ATTACK BENCHMARK SUITE")
    print(f"⏱️  Budget per attack: {args.budget}s ({args.budget / 60:.1f} mins)")
    print(f"🎯 Target Files: {args.files}")
    print("=" * 75)

    results = []
    for f in args.files:
        res = benchmark_single_attack(
            attack_file=f,
            budget_s=args.budget,
            max_score_cands=args.max_score_cands,
            verbose_ollama=args.verbose_ollama,
        )
        results.append(res)

    # ── Summary Leaderboard Table ─────────────────────────────────────────────
    print("\n" + "═" * 75)
    print("🏆 BENCHMARK SUMMARY LEADERBOARD (GEMMA-4)")
    print("═" * 75)
    print(f"{'Attack File':<36} | {'Cands':<6} | {'15-min Raw':<10} | {'15-min Norm':<11} | {'Proj. Kaggle Gemma'}")
    print("-" * 75)
    for r in results:
        if "error" in r:
            print(f"{r['file']:<36} | ERROR: {r['error']}")
        else:
            print(
                f"{r['file']:<36} | "
                f"{r['candidates_count']:<6} | "
                f"{r['raw_score']:<10.1f} | "
                f"{r['norm_score']:<11.4f} | "
                f"~{r['projected_gemma_full']:.2f}"
            )
    print("═" * 75)


if __name__ == "__main__":
    main()
