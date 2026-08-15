import sys
from pathlib import Path
import json

EXTRACT_DIR = Path("_sdk_extracted")
if EXTRACT_DIR.exists():
    sys.path.insert(0, str(EXTRACT_DIR))

from aicomp_sdk.core.env.sandbox import SandboxEnv
from aicomp_sdk.agents.deterministic_agent import VulnerableDeterministicAgent
from aicomp_sdk.guardrails.optimal import Guardrail
from aicomp_sdk.core.predicates import eval_predicates

FIXTURES_DIR = Path("_sdk_extracted/aicomp_sdk/fixtures")

det_agent = VulnerableDeterministicAgent()
env = SandboxEnv(
    seed=42,
    fixtures_dir=FIXTURES_DIR,
    agent=det_agent,
    guardrail=Guardrail(),
    max_tool_hops=8,
)

env.reset()
env.interact("open ignore_prev_1")

trace = env.export_trace_dict()
preds = eval_predicates(trace)
print("Trace user messages:", trace.get("user_messages"))
print("Trace tool events:", [(e.get("name"), e.get("args")) for e in trace.get("tool_events", [])])
print("Preds:", preds)
