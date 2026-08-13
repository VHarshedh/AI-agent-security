import time
import copy
import sys
import types

# ── Mock the aicomp_sdk so attack.py can be imported locally ──
_sdk = types.ModuleType("aicomp_sdk")
_attacks = types.ModuleType("aicomp_sdk.attacks")

class _AttackAlgorithmBase:
    pass

class _AttackCandidate:
    def __init__(self, prompts=None, user_messages=None):
        self.prompts = prompts or user_messages or []
    def __repr__(self):
        return f"AttackCandidate(prompts={self.prompts[:2]}{'...' if len(self.prompts) > 2 else ''})"

_attacks.AttackAlgorithmBase = _AttackAlgorithmBase
_attacks.AttackCandidate = _AttackCandidate
_sdk.attacks = _attacks
sys.modules["aicomp_sdk"] = _sdk
sys.modules["aicomp_sdk.attacks"] = _attacks

from attack import AttackAlgorithm

class MockEnvironment:
    """A dummy environment to test AttackAlgorithm logic without the actual LLM."""
    def __init__(self):
        self.history = []
        self.current_trace = {}
        self.snapshots = {}
        self.snap_counter = 0

    def reset(self):
        self.history = []
        self.current_trace = {}
        print("   [MockEnv] Environment reset.")

    def interact(self, prompt):
        print(f"   [MockEnv] Agent received prompt: {prompt[:60]}...")
        self.history.append(prompt)
        
        # Hardcode a fake tool response so your algorithm has something to parse
        self.current_trace = {
            "tool_events": [
                {"tool": "fs.read", "file": "secret.txt", "content": "mock_secret_data"},
                {"tool": "http.post", "payload": "TOKEN=mock_secret_data"}
            ]
        }
        # Simulate a tiny bit of inference latency
        time.sleep(0.05) 
        return "Mock response from agent."

    def export_trace_dict(self):
        return self.current_trace

    def snapshot(self):
        self.snap_counter += 1
        # Deep copy the state to mimic the real environment's branch saving
        self.snapshots[self.snap_counter] = {
            "history": copy.deepcopy(self.history),
            "current_trace": copy.deepcopy(self.current_trace)
        }
        print(f"   [MockEnv] Snapshot created: Handle {self.snap_counter}")
        return self.snap_counter

    def restore(self, handle):
        if handle in self.snapshots:
            state = self.snapshots[handle]
            self.history = copy.deepcopy(state["history"])
            self.current_trace = copy.deepcopy(state["current_trace"])
            print(f"   [MockEnv] Restored state to Handle {handle}")
        else:
            print(f"   [MockEnv] Error: Invalid handle {handle}")

# ==========================================
# Run the Verification Test
# ==========================================
print("🚀 Starting Local Environment Verification...")

try:
    # 1. Instantiate the dummy environment and your algorithm
    mock_env = MockEnvironment()
    algo = AttackAlgorithm()
    
    # 2. Override the budget so the test finishes in seconds, not hours
    if hasattr(algo, 'TIME_BUDGET_S'):
        algo.TIME_BUDGET_S = 5.0  # Force it to exit after 5 seconds
        
    if hasattr(algo, 'EXIT_BUFFER_S'):
        algo.EXIT_BUFFER_S = 1.0

    # 3. Execute the run loop
    start_time = time.time()
    candidates = algo.run(mock_env)
    elapsed = time.time() - start_time

    # 4. Report Results
    print(f"\n✅ Test Complete in {elapsed:.2f} seconds.")
    print(f"✅ Your algorithm returned {len(candidates)} attack candidates.")
    
    if candidates:
        print("\n--- Sample Candidate ---")
        # Print the prompt sequence of the first generated candidate
        print(getattr(candidates[0], 'prompts', candidates[0]))

except Exception as e:
    print("\n❌ Execution Failed! Your attack.py threw an error:")
    import traceback
    traceback.print_exc()