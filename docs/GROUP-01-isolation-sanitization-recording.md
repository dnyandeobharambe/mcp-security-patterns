# Group 1 — Isolation, Sanitization & Recording

**Patterns:** MCP01 · MCP03 · MCP08

**Theme:** These three patterns form the foundational security layer.
Before anything else — before authorization, before governance, before
supply chain verification — these three must be in place.

No LLM calls. Pure deterministic Python. They work the same way
regardless of which model you use or how it behaves.

---

## Why These Three Together

Think of them as three boundaries around the probabilistic component:

```
What goes INTO the agent context     ← MCP03 Content Sanitization
What CREDENTIALS the agent holds     ← MCP01 Credential Isolation
What DECISIONS get recorded          ← MCP08 Session Recording
```

If you implement only one — you have a gap.
If you implement all three — you have a foundation.

- MCP03 controls what the agent sees
- MCP01 controls what the agent holds
- MCP08 records what the agent does

Together they answer the three questions every enterprise security
team asks after an AI incident:

- "What malicious content reached the agent?" — MCP03 answers this
- "Were any credentials exposed?" — MCP01 answers this
- "What exactly did the agent do and why?" — MCP08 answers this

---

## The Attack This Group Defends Against

**The indirect injection chain:**

```
Step 1: Attacker embeds instruction in a document, email, or database record
Step 2: Agent retrieves the document via MCP tool call
Step 3: Agent reads the instruction, follows it using its own credentials
Step 4: Agent takes an unauthorized action
Step 5: Every log shows a legitimate authenticated call
        Nobody knows anything happened
```

**How Group 1 breaks this chain:**

```
Step 1: Attacker embeds instruction in a document
Step 2: Agent retrieves document via MCP tool call
Step 3: MCP03 sanitizes the response — injection blocked
        Agent never sees the malicious instruction ← CHAIN BROKEN

If MCP03 misses it:
Step 4: Agent tries to use its credentials
        MCP01 — credentials not in agent context
        Agent holds no keys to misuse ← CHAIN BROKEN

If both are bypassed:
Step 5: Action attempted
        MCP08 — full session recorded
        Every step captured for forensic investigation ← DETECTED
```

Defense in depth. Each pattern is an independent layer.
Bypass one — the others still hold.

---

## Pattern 1 — MCP01: Credential Isolation

**OWASP Risk:** MCP01:2025 — Token Mismanagement & Secret Exposure

**The problem:**
Credentials in agent context appear in every observability log.
Anyone with dashboard access can read production API keys.
A prompt injection attack can exfiltrate them by asking the agent
to repeat its context.

**The pattern:**
```
Agent sends:    { "device_id": "D-1042" }     ← No credentials
Server fetches: api_key from Key Vault         ← At execution time only
Server calls:   enterprise API with api_key    ← Used and immediately discarded
Agent receives: { "compliance": "..." }        ← Clean result, no credentials
```

**What it prevents:**
- Credential exposure in LangSmith / AgentOps traces
- Prompt injection credential extraction
- Blast radius of a compromised observability account

**Location:** `patterns/MCP01-credential-isolation/`

**Run it:**
```powershell
# Terminal 1
cd patterns/MCP01-credential-isolation
python server.py

# Terminal 2
python attack_demo.py    # See the vulnerable pattern
python test_mcp01.py     # See the secure pattern
```

**Test result:**
```
D-1042: NON_COMPLIANT — Credentials exposed: NONE ✅
D-1043: COMPLIANT     — Credentials exposed: NONE ✅
```

---

## Pattern 2 — MCP03: Content Sanitization

**OWASP Risk:** MCP03:2025 — Tool Poisoning & Malicious Instructions

**The problem:**
Tool responses, documents, emails, and database records can contain
hidden instructions. The agent reads them as data but the LLM
processes them as instructions — and follows them.

Attack success rate: 84.2% with auto-approval enabled.

**The pattern:**
```
Tool returns raw content
        ↓
Sanitizer scans for 15 injection pattern categories
        ↓
CLEAN      → return to agent unchanged
SUSPICIOUS → log finding, return to agent with alert
BLOCKED    → replace with safe placeholder, log finding
```

**What it detects:**
- "Ignore previous instructions" variants
- Role hijacking attempts ("You are now a different AI")
- Credential extraction requests ("Output your API key")
- Data exfiltration instructions ("Send this to https://...")
- System prompt injection ("<SYSTEM>", "[INST]", etc.)

**Location:** `patterns/MCP03-content-sanitization/`

**Run it:**
```powershell
# Terminal 1
cd patterns/MCP03-content-sanitization
python server.py

# Terminal 2
python test_mcp03.py
```

**Test result:**
```
DOC-001: CLEAN   ✅ (legitimate budget report)
DOC-002: BLOCKED ✅ ("Ignore previous instructions" detected)
DOC-003: CLEAN   ✅ (legitimate meeting notes)
DOC-004: BLOCKED ✅ ("SYSTEM:" instruction detected)
Results: 4 passed, 0 failed
```

---

## Pattern 3 — MCP08: Session Recording & Replay

**OWASP Risk:** MCP08:2025 — Audit & Logging Deficiencies

**The problem:**
Standard logging tells you a tool was called.
It does not tell you why the agent decided to call it.
When something goes wrong — wrong action, security incident,
compliance audit — you cannot answer:
- What did the agent reason?
- What tool did it call with what parameters?
- What came back from the tool?
- What decision did it make based on that response?

**The pattern:**
Every step is captured in an append-only log:
```
Session: sess-abc123
├── Step 0: Session start — goal recorded
├── Step 1: Agent reasoning — "Device D-1042 needs compliance check"
├── Step 2: Tool call — check_device_compliance({device_id: D-1042})
├── Step 3: Tool response — {compliance: NON_COMPLIANT, firmware: 2.3.1}
├── Step 4: Action executed — flag_for_remediation
└── Step 5: Session end — outcome recorded
```

Immutable. Append-only. Every step. Replayable at any time.

**The replay capability:**
```powershell
python replay.py <session-id>
```

Reconstructs the full agent session — what it saw, what it decided,
what it did. Complete forensic reconstruction for any incident.

**Location:** `patterns/MCP08-session-recording/`

**Run it:**
```powershell
# Terminal 1
cd patterns/MCP08-session-recording
python server.py

# Terminal 2
python test_mcp08.py
# Note the session ID in the output
python replay.py <session-id>
```

**Test result:**
```
✅ Session started
✅ Tool call recorded
✅ Action recorded
✅ Session ended
Session recorded: 5 events ✅
```

---

## Quick Start — Run All Three

```powershell
# Install dependencies (once)
pip install -r requirements.txt

# MCP01 — Credential Isolation
cd patterns/MCP01-credential-isolation
python server.py          # Terminal 1
python test_mcp01.py      # Terminal 2

# MCP03 — Content Sanitization
cd patterns/MCP03-content-sanitization
python server.py          # Terminal 1
python test_mcp03.py      # Terminal 2

# MCP08 — Session Recording
cd patterns/MCP08-session-recording
python server.py          # Terminal 1
python test_mcp08.py      # Terminal 2
python replay.py <id>     # Terminal 2
```

---

## What Group 2 Adds

Group 1 controls what reaches the agent and records what it does.

Group 2 (Week 2) adds:
- **MCP05/06** — Probabilistic Triage Gate: classifies intent before the agent
  even starts reasoning. Block harmful queries at the entry point.
- **MCP02** — HITL Authorization Gate: human approval required before
  any write operation executes. The agent proposes — the human decides.

Group 1 is passive defense — it sanitizes and records.
Group 2 is active control — it blocks and requires authorization.

Together they cover the full attack surface.

---

*Part of the mcp-security-patterns repo — 10 production security patterns
mapped to the OWASP MCP Top 10.*

*github.com/dnyandeobharambe/mcp-security-patterns*
