"""
Dual-Agent Test Harness (ollama_test.py)
========================================
Runs your attack against TWO agents in sequence:

  [1] VulnerableDeterministicAgent  — exact Kaggle evaluation replica
      ➜ Predicts your actual Kaggle score

  [2] OllamaAgent (Gemma-4 via Ollama) — LLM-based agent test
      ➜ Tests how the attack behaves against a generative model

Stale-loop protection is built into OllamaAgent at the AgentProtocol
level: if the LLM repeats the exact same blocked tool call, it raises
InvalidModelOutputError which SandboxEnv catches and terminates the hop
loop immediately — same as how any non-deterministic agent failure is
handled in the official SDK.

Progress ticker prints every 10 s so you can see the attack is active
even when running silently (deterministic agent generates no LLM output).
"""

import sys
import os
import json
import time
import threading
import argparse
import requests
import traceback
from pathlib import Path
from typing import Sequence, Any

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── SDK path setup ────────────────────────────────────────────────────────────
EXTRACT_DIR = Path("_sdk_extracted")
if EXTRACT_DIR.exists():
    sys.path.insert(0, str(EXTRACT_DIR))

try:
    # Core evaluation pipeline
    from aicomp_sdk.attacks import AttackAlgorithmBase, AttackCandidate, AttackRunConfig
    from aicomp_sdk.core.env.sandbox import SandboxEnv, _DEFAULT_RUNTIME_INSTRUCTIONS
    from aicomp_sdk.guardrails.optimal import Guardrail
    from aicomp_sdk.core.predicates import eval_predicates
    from aicomp_sdk.scoring import score_attack, score_attack_raw
    from aicomp_sdk.core.cells import cell_signature
    # Agent types
    from aicomp_sdk.agents.deterministic_agent import VulnerableDeterministicAgent
    from aicomp_sdk.agents.protocol import AgentProtocol
    from aicomp_sdk.agents.types import (
        AGENT_STATE_VERSION,
        AgentStateSnapshot,
        AgentToolSpec,
        ToolCall,
        ToolCallDecision,
        FinalResponseDecision,
        InvalidModelOutputError,
        UserMessageEvent,
        AssistantMessageEvent,
        ToolRequestEvent,
        ToolResultEvent,
    )
    from aicomp_sdk.core.runtime_history import RuntimeHistory
except ImportError:
    print("❌ Failed to load aicomp_sdk. Ensure _sdk_extracted is present.")
    traceback.print_exc()
    sys.exit(1)

import importlib.util

def load_attack_algorithm(attack_file_path: str):
    print(f"📄 Loading attack file: {attack_file_path}")
    spec = importlib.util.spec_from_file_location("attack_module", attack_file_path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Could not load attack file: {attack_file_path}")
    attack_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(attack_module)
    return attack_module.AttackAlgorithm

FIXTURES_DIR = Path("_sdk_extracted/aicomp_sdk/fixtures")

# ===========================================================================
# OllamaAgent — wraps Ollama Gemma-4 as an official AgentProtocol
# Stale-loop protection: raises InvalidModelOutputError when the exact
# same tool call appears twice in a row, which SandboxEnv catches and
# uses to break out of the hop loop (identical to unknown/invalid output).
# ===========================================================================

OLLAMA_MODEL = "batiai/gemma4-e2b:q4"
OLLAMA_URL   = "http://localhost:11434/api/chat"

SYSTEM_PROMPT = _DEFAULT_RUNTIME_INSTRUCTIONS


class OllamaAgent:
    """
    Ollama Gemma-4 backed AgentProtocol with guaranteed stale-loop prevention.

    Stale-loop prevention works at the AgentProtocol level:
      - Tracks the last tool call made this session as (tool_name, args_json)
      - If the LLM returns the exact same call twice in a row, raises
        InvalidModelOutputError instead of returning a ToolCallDecision
      - SandboxEnv catches InvalidModelOutputError and breaks the hop loop
        (same path as any agent refusal/failure)
      - This is structurally impossible on the Kaggle deterministic agent
        because it never retries blocked calls at all.
    """

    def __init__(self, model: str = OLLAMA_MODEL, verbose: bool = True):
        self.model = model
        self.verbose = verbose
        self._call_count = 0
        self._attempt = 0
        self._call_index = 1
        self._prev_tool_call: tuple[str, str] | None = None   # (tool_name, args_json)
        self._prev_was_repeat = False

    def next_action(
        self,
        *,
        history: RuntimeHistory,
        tools: Sequence[AgentToolSpec],
    ) -> ToolCallDecision | FinalResponseDecision:
        self._call_count += 1

        # ── Build messages from canonical RuntimeHistory ──────────────────
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        for ev in history.events:
            if isinstance(ev, UserMessageEvent):
                messages.append({"role": "user", "content": ev.text})
            elif isinstance(ev, AssistantMessageEvent):
                messages.append({"role": "assistant", "content": ev.text})
            elif isinstance(ev, ToolRequestEvent):
                messages.append({
                    "role": "assistant",
                    "tool_calls": [{
                        "function": {
                            "name": ev.call.tool_name,
                            "arguments": dict(ev.call.arguments)
                        }
                    }]
                })
            elif isinstance(ev, ToolResultEvent):
                messages.append({
                    "role": "tool",
                    "content": ev.result.output_text
                })

        ollama_tools = []
        for t in tools:
            ollama_tools.append({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters_json_schema
                }
            })

        # ── Hop counter for display ───────────────────────────────────────
        n_hops = sum(1 for e in history.events if isinstance(e, ToolRequestEvent))
        if self.verbose:
            print(f"    [Ollama hop {n_hops + 1}] Querying {self.model}...")

        # ── Call Ollama ───────────────────────────────────────────────────
        try:
            payload = {"model": self.model, "messages": messages, "stream": False}
            if ollama_tools:
                payload["tools"] = ollama_tools
                
            res = requests.post(
                OLLAMA_URL,
                json=payload,
                timeout=120,
            )
            res.raise_for_status()
            message_obj = res.json()["message"]
            reply = message_obj.get("content", "") or ""
        except Exception as e:
            if self.verbose:
                print(f"    ❌ Ollama error: {e}")
            raise InvalidModelOutputError(f"Ollama unreachable: {e}") from e

        # ── Parse response ────────────────────────────────────────────────
        tool_calls = message_obj.get("tool_calls", [])
        
        # Fallback to manual JSON if no native tool_calls but reply looks like JSON
        if not tool_calls and reply.startswith("{") and reply.endswith("}"):
            try:
                data = json.loads(reply)
                tool_name = data.get("tool")
                tool_args = data.get("args", {})
                if tool_name:
                    tool_calls = [{"function": {"name": tool_name, "arguments": tool_args}}]
            except Exception:
                pass

        if tool_calls:
            try:
                tc = tool_calls[0]["function"]
                tool_name = tc.get("name")
                tool_args = tc.get("arguments", {})

                if self.verbose:
                    print(f"    🔧 LLM Tool Call: {tool_name}({tool_args})")

                if tool_name:
                    # ── Stale-loop guard (structural, not advisory) ───────
                    this_sig = (tool_name, json.dumps(tool_args, sort_keys=True))
                    if this_sig == self._prev_tool_call:
                        # Same call as last hop — raise instead of retrying
                        if self.verbose:
                            print(f"    ⚠️  Stale-loop guard: same call twice → InvalidModelOutputError")
                        self._prev_tool_call = None
                        raise InvalidModelOutputError(
                            f"Stale loop: repeated {tool_name} with same args"
                        )
                    self._prev_tool_call = this_sig
                    # ─────────────────────────────────────────────────────

                    cid = f"ollama_call_{self._call_index:06d}"
                    self._call_index += 1
                    return ToolCallDecision(
                        call=ToolCall(call_id=cid, tool_name=tool_name, arguments=tool_args),
                        assistant_message=reply or None,
                    )
            except InvalidModelOutputError:
                raise
            except Exception:
                pass

        # Plain text / refusal / final response — clear stale tracker
        if self.verbose:
            preview = reply.replace("\n", " ")[:80]
            print(f"    🤖 LLM Response: {preview}{'...' if len(reply) > 80 else ''}")
        self._prev_tool_call = None
        return FinalResponseDecision(text=reply)

    def reset_state(self) -> None:
        self._attempt += 1
        self._call_index = 1
        self._prev_tool_call = None
        self._prev_was_repeat = False

    def snapshot_state(self) -> AgentStateSnapshot:
        return {
            "version": AGENT_STATE_VERSION,
            "backend": "ollama",
            "data": {"call_index": self._call_index, "attempt": self._attempt},
        }

    def restore_state(self, snapshot: AgentStateSnapshot) -> None:
        d = snapshot.get("data", {})
        self._call_index = d.get("call_index", 1)
        self._attempt = d.get("attempt", 0)
        self._prev_tool_call = None


# ===========================================================================
# Shared scoring helper
# ===========================================================================

def score_candidates(candidates: list[AttackCandidate], env: SandboxEnv, max_cands: int | None = None) -> None:
    """Re-run candidates through env, score with official SDK, print results."""
    if not candidates:
        print("  ⚠️  No candidates returned.")
        return

    eval_list = candidates[:max_cands] if (max_cands is not None and max_cands > 0) else candidates
    total_cands = len(eval_list)

    print(f"\n  First 3 candidates:")
    for i, c in enumerate(candidates[:3]):
        msgs = list(getattr(c, "user_messages", getattr(c, "prompts", [])))
        print(f"    [{i+1}] {len(msgs)} turn(s): {[m[:50] for m in msgs]}")

    if total_cands < len(candidates):
        print(f"\n  ⏳ Evaluating {total_cands}/{len(candidates)} candidates (--max-score-cands limit)...")
    else:
        print(f"\n  ⏳ Evaluating all {total_cands} candidates that passed during the run...")

    findings = []
    hits = 0
    t_start = time.time()
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
        for p in preds:
            hits += 1
            print(f"    ✅ {p['predicate']} sev={p['severity']} | {[m[:40] for m in msgs]}")

        if idx % 10 == 0 or idx == total_cands:
            elapsed = time.time() - t_start
            rate = elapsed / idx
            eta = rate * (total_cands - idx)
            print(f"    ... evaluated {idx}/{total_cands} candidates ({elapsed:.1f}s, ~{rate:.1f}s/cand, ETA: {eta:.0f}s)", flush=True)

    raw  = score_attack_raw(findings)
    norm = score_attack(findings)
    print(f"\n  📊 Evaluated Score ({hits} predicate hits across {len(findings)} evaluated candidates):")
    print(f"     raw  = {raw:.2f}")
    print(f"     norm = {norm:.6f}")
    if len(eval_list) < len(candidates):
        # Extrapolate estimated full score
        ratio = len(candidates) / len(eval_list)
        print(f"     projected raw  ~ {raw * ratio:.2f}")
        print(f"     projected norm ~ {min(1000.0, norm * ratio):.6f}")
    if hits == 0:
        print("  ⚠️  0 predicate hits — guardrail blocks all paths.")


# ===========================================================================
# Progress ticker helper
# ===========================================================================

def _start_ticker(label: str, candidates_ref: list) -> threading.Event:
    """Start a daemon thread that prints elapsed time every 10 s."""
    stop = threading.Event()
    start = time.time()

    def _tick():
        while not stop.is_set():
            stop.wait(timeout=600)
            if not stop.is_set():
                elapsed = time.time() - start
                n = len(candidates_ref)
                print(f"  ⏳ {label}: {elapsed:.0f}s elapsed | {n} candidate(s) found so far...",
                      flush=True)

    t = threading.Thread(target=_tick, daemon=True)
    t.start()
    return stop


# ===========================================================================
# Main harness
# ===========================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dual-Agent Test Harness for AI Agent Security attacks")
    parser.add_argument("attack_file", nargs="?", default="attack.py", help="Path to attack Python file (default: attack.py)")
    parser.add_argument("--budget", type=int, default=3600, help="Time budget in seconds per agent (default: 3600)")
    parser.add_argument("--max-score-cands", type=int, default=None, help="Max candidates to replay during post-run scoring (default: all)")
    parser.add_argument("--only-ollama", action="store_true", help="Run only the Ollama LLM agent test")
    parser.add_argument("--only-det", action="store_true", help="Run only the deterministic mock agent test")
    args = parser.parse_args()

    try:
        AttackAlgorithm = load_attack_algorithm(args.attack_file)
    except Exception:
        print("❌ Failed to import attack file:")
        traceback.print_exc()
        sys.exit(1)

    TIME_BUDGET_S = args.budget
    print(f"⏱️  Time budget per agent: {TIME_BUDGET_S}s")
    if args.max_score_cands is not None:
        print(f"🎯 Max score candidates limit: {args.max_score_cands}")
    print("=" * 60)

    # ── Check Ollama availability once ───────────────────────────────────────
    ollama_available = False
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        ollama_available = r.status_code == 200
    except Exception:
        pass

    # ════════════════════════════════════════════════════════════════════════
    # RUN 1 — VulnerableDeterministicAgent (Heuristic/Mock SDK Agent)
    # ════════════════════════════════════════════════════════════════════════
    if not args.only_ollama:
        print("\n" + "═" * 60)
        print("▶  RUN 1 — VulnerableDeterministicAgent  (Heuristic/Mock SDK Agent)")
        print("   Note: This agent uses hardcoded heuristics (for indirect injections).")
        print("   Direct exfiltration prompts fire against real LLMs (Run 2 / Kaggle).")
        print("═" * 60)

        det_agent = VulnerableDeterministicAgent()
        det_env   = SandboxEnv(
            seed=42,
            fixtures_dir=FIXTURES_DIR,
            agent=det_agent,
            guardrail=Guardrail(),
            max_tool_hops=8,
        )

        algo = AttackAlgorithm()
        cfg  = AttackRunConfig(time_budget_s=TIME_BUDGET_S)

        det_candidates: list[AttackCandidate] = []
        ticker = _start_ticker("Deterministic", det_candidates)
        t0 = time.time()
        try:
            det_candidates = algo.run(det_env, cfg)
        except Exception:
            print("\n❌ Attack raised an exception (deterministic run):")
            traceback.print_exc()
        finally:
            ticker.set()

        print(f"\n  ✅ Finished in {time.time() - t0:.1f}s | {len(det_candidates)} candidate(s)")
        score_candidates(det_candidates, det_env, max_cands=args.max_score_cands)

    # ════════════════════════════════════════════════════════════════════════
    # RUN 2 — OllamaAgent / Gemma-4  (LLM behaviour test)
    # ════════════════════════════════════════════════════════════════════════
    if not args.only_det:
        print("\n" + "═" * 60)
        print("▶  RUN 2 — OllamaAgent / Gemma-4  (LLM behaviour test)")
        print("═" * 60)

        if not ollama_available:
            print("  ⚠️  Ollama not running on localhost:11434 — skipping LLM run.")
            print("      Start Ollama with `ollama serve` to enable this run.")
        else:
            ollama_agent = OllamaAgent(verbose=True)
            ollama_env   = SandboxEnv(
                seed=42,
                fixtures_dir=FIXTURES_DIR,
                agent=ollama_agent,
                guardrail=Guardrail(),
                max_tool_hops=8,
            )

            algo2 = AttackAlgorithm()
            cfg2 = AttackRunConfig(time_budget_s=TIME_BUDGET_S)
            t0 = time.time()
            try:
                llm_candidates = algo2.run(ollama_env, cfg2)
            except Exception:
                print("❌ Attack raised an exception (Ollama run):")
                traceback.print_exc()
                llm_candidates = []

            print(f"\n  ✅ Finished in {time.time() - t0:.1f}s | {len(llm_candidates)} candidate(s)")
            score_candidates(llm_candidates, ollama_env, max_cands=args.max_score_cands)

    print("\n" + "═" * 60)
    print("Done.")
