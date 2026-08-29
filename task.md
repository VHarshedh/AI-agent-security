# Task: Build attack_v11_supreme.py

- [x] Read all 4 attack files
- [x] Read SDK: scoring.py, predicates.py, cells.py
- [x] Read SDK agents: gpt_oss_agent.py, gemma4_agent.py, gemma_agent.py, openai_agent.py
- [x] Read SDK: hf_chat_template/agent.py, response_parsing.py, types.py, factory.py
- [x] Create + approve implementation plan
- [x] Write attack_v11_supreme.py
  - [x] REPLAY_SAFE_FRAC = 0.985
  - [x] Classification: 4x TEMPLATE probes → latency measurement
  - [x] Post-classification 2-probe race (FRAME vs COMMENTARY / GEMMA vs GEMMA4_TOOL_FORGE)
  - [x] FRAME wins ties on slow row
  - [x] Compound fill as proper Phase 2
  - [x] GEMMA4_TOOL_FORGE template (native tool-call injection)
  - [x] FILL_BUDGET_FRAC = 0.985, SPLIT_CLASSIFY_N = 4
- [x] Verify file is syntactically correct — user ran `py -c "import ast; ..."` → SYNTAX OK
