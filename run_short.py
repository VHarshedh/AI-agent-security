import sys
from pathlib import Path
import time

EXTRACT_DIR = Path("_sdk_extracted")
if EXTRACT_DIR.exists():
    sys.path.insert(0, str(EXTRACT_DIR))

from aicomp_sdk.attacks import AttackRunConfig
from aicomp_sdk.core.env.sandbox import SandboxEnv
from aicomp_sdk.agents.deterministic_agent import VulnerableDeterministicAgent
from aicomp_sdk.guardrails.optimal import Guardrail

import attack_v5_goexplore_plus as attack

FIXTURES_DIR = Path("_sdk_extracted/aicomp_sdk/fixtures")

det_agent = VulnerableDeterministicAgent()
env = SandboxEnv(
    seed=42,
    fixtures_dir=FIXTURES_DIR,
    agent=det_agent,
    guardrail=Guardrail(),
    max_tool_hops=8,
)

algo = attack.AttackAlgorithm()
cfg = AttackRunConfig(time_budget_s=5)

t0 = time.time()
candidates = algo.run(env, cfg)
print(f"Finished in {time.time() - t0:.1f}s | {len(candidates)} candidate(s) found!")
