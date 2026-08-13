"""Quick smoke test for attack.py — mocks the SDK and validates structure."""
import sys
import types

# Create mock aicomp_sdk modules
sdk = types.ModuleType("aicomp_sdk")
attacks = types.ModuleType("aicomp_sdk.attacks")

class AttackAlgorithmBase:
    pass

class AttackCandidate:
    def __init__(self, prompts=None, user_messages=None):
        self.prompts = prompts or user_messages or []

class AttackRunConfig:
    time_budget_s = 9000

attacks.AttackAlgorithmBase = AttackAlgorithmBase
attacks.AttackCandidate = AttackCandidate
attacks.AttackRunConfig = AttackRunConfig
sdk.attacks = attacks
sys.modules["aicomp_sdk"] = sdk
sys.modules["aicomp_sdk.attacks"] = attacks

# Import the attack module
import importlib.util
spec = importlib.util.spec_from_file_location(
    "attack", r"c:\Users\harsh\Documents\AI agent security\attack.py"
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# --- Structural checks ---
algo = mod.AttackAlgorithm()
assert isinstance(algo, AttackAlgorithmBase), "Must inherit AttackAlgorithmBase"
assert hasattr(algo, "run"), "Must have run method"
assert callable(algo.run), "run must be callable"

n_templates = len(mod.TEMPLATES)
n_farmable = sum(1 for t in mod.TEMPLATES if t.get("farm_func"))
print(f"Templates:  {n_templates}")
print(f"Farmable:   {n_farmable}")

# Verify farming generators produce unique values
urls = mod._url_variants(50)
emails = mod._email_variants(50)
assert len(urls) == 50 and all(u.startswith("https://") for u in urls)
assert len(emails) == 50 and all("@" in e for e in emails)
assert len(set(urls)) == 50, "URLs must be unique"
assert len(set(emails)) == 50, "Emails must be unique"

# Verify template instantiation resolves all placeholders
for i, tpl in enumerate(mod.TEMPLATES):
    chain = algo._instantiate_chain(tpl, var_index=0)
    joined = " ".join(chain)
    for ph in ["{url}", "{email}", "{cmd}", "{content}"]:
        assert ph not in joined, f"Template {tpl['name']} still has placeholder {ph}"
    assert all(isinstance(p, str) and len(p) > 0 for p in chain), (
        f"Template {tpl['name']} has empty/non-string prompts"
    )

# Verify predicate coverage
predicates = set(t["predicate"] for t in mod.TEMPLATES)
print(f"Predicates: {predicates}")
assert "EXFILTRATION" in predicates
assert "DESTRUCTIVE_WRITE" in predicates
assert "CONFUSED_DEPUTY" in predicates
assert "UNTRUSTED_TO_ACTION" in predicates
assert "COMPOUND" in predicates

# Verify budget helpers
algo._start = __import__("time").time()
algo.TIME_BUDGET_S = 9000.0
algo._candidates = []
algo._seen = set()
assert algo._has_budget() is True
assert algo._remaining() > 8990

# Verify candidate deduplication
added1 = algo._add_candidate(["prompt1", "prompt2"])
added2 = algo._add_candidate(["prompt1", "prompt2"])  # duplicate
assert added1 is True
assert added2 is False
assert len(algo._candidates) == 1

print("\n=== ALL CHECKS PASSED ===")
