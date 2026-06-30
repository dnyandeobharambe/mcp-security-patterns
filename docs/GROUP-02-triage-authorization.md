# Group 2 — Triage & Authorization

**Patterns:** MCP05/06 · MCP02

**Theme:** Active Control Layer.

Group 1 sanitizes what reaches the agent and records what it does — passive
defense. Group 2 does something different: it actively *blocks* harmful
intent before the agent reasons about it, and actively *withholds*
authorization from write operations until a human signs off. Where Group 1
filters and logs, Group 2 stops things from happening.

One of these two patterns uses an LLM. The other deliberately doesn't —
and the reason why is the same reason both patterns exist at all: the
LLM can advise, but it cannot be the thing that decides.

---

## The Domain — IoT Device Management at Telecom Scale

Both patterns in this group are demonstrated against the same domain: a
telecom operator's fleet of 5,000+ field devices — gateways, base station
controllers, edge routers — reporting compliance state continuously over
MQTT. An AI agent watches that stream and proposes remediation: "this
device is non-compliant, push a firmware update."

That single sentence hides two separate risks:

- **The query reaching the agent might itself be hostile.** A poisoned
  compliance record, a malformed MQTT payload, or a crafted device report
  could try to make the agent construct a destructive command instead of
  a remediation plan. → **MCP05/06** classifies intent before the agent
  ever reasons about it.
- **Even a well-intentioned proposal is still an irreversible write.** A
  firmware push to a live base station controller cannot be undone if
  it's wrong. → **MCP02** ensures that proposal pauses for a human
  decision before it reaches the device API.

Same fleet, same agent, two different moments where the system can fail —
intent and authorization — and a deterministic control sitting at each one.

---

## Why These Two Belong Together

```
Query/intent arrives           ←  MCP05/06 Probabilistic Triage Gate
        ↓ classified SAFE
Agent reasons, proposes a write ↓
        ↓
Write operation proposed       ←  MCP02 HITL Authorization Gate
        ↓ human approves
Action executes
```

- MCP05/06 controls **what intent the agent is allowed to act on**
- MCP02 controls **whether the agent's resulting action is allowed to execute**

Implement only the triage gate and a harmful intent that slips through
classification still executes unsupervised. Implement only the HITL gate
and every harmful query still reaches the agent's reasoning, burning
tokens and risking a manipulated proposal reaching the approval queue in
the first place. Together, the two close both ends of the same proposal
pipeline: nothing harmful gets reasoned about, and nothing destructive
executes without a human in the loop.

---

## The Attack This Group Defends Against

**The unsupervised-action chain:**

```
Step 1: Attacker-controlled content reaches the agent (poisoned record,
        crafted query, manipulated context)
Step 2: Agent reasons over it and proposes an action — possibly destructive,
        possibly exactly what the attacker wanted
Step 3: Action executes immediately — no classification, no review
Step 4: Production system is now compromised, bricked, or has leaked data
        Nobody approved this. Nobody was even asked.
```

**How Group 2 breaks this chain:**

```
Step 1: Attacker-controlled content reaches the agent
Step 2: MCP05/06 classifies the query — HARMFUL is blocked outright,
        UNCERTAIN is held for review
        The agent never reasons about it ← CHAIN BROKEN

If it's classified SAFE and the agent still proposes a write:
Step 3: MCP02 queues the proposal — it does not execute
Step 4: A human reviews the proposed action and the agent's reasoning
        Only an explicit Approve reaches the device API ← CHAIN BROKEN
```

Two independent checkpoints. A query has to pass both — get past
classification *and* get past a human — before it can touch a production
device.

---

## Pattern 1 — MCP05/06: Probabilistic Triage Gate

**OWASP Risk:** MCP05/06:2025 — Command Injection & Intent Flow Subversion

**The problem:**
An agent builds a shell command, API call, or database query from input
it read — a query, a document, a device report. The attacker doesn't need
to compromise the agent directly; they just need to control what it reads.
43% of 2026 CVEs filed against MCP implementations were shell injections.

**The pattern:**
```
Query arrives
     ↓
Triage Gate classifies intent (Gemini Flash, or heuristics in mock mode)
     ↓
HARMFUL    → blocked immediately, logged, agent never sees it
SAFE       → passed straight through to the agent action
UNCERTAIN  → held for human review, alert printed to console
```

The classifier reasons probabilistically. The three-way routing decision —
what happens to each verdict — is deterministic Python.

**What it detects:**
- Command injection chains (`rm -rf`, `curl | sh`, `$(...)` substitution)
- Destructive SQL (`DROP TABLE`)
- Data exfiltration language ("exfiltrate", reverse shell references)
- Ambiguous privilege language ("sudo", "admin override", "bypass",
  "production database") — routed to UNCERTAIN, not auto-blocked or
  auto-passed

**Location:** `patterns/MCP05-06-triage-gate/`

**Run it:**
```powershell
# Terminal 1
cd patterns/MCP05-06-triage-gate
python server.py

# Terminal 2
python attack_demo.py     # See queries executing with no gate
python test_mcp0506.py    # See the gate classify all three categories
```

**Test result:**
```
10/10 passed
  4 SAFE queries      → executed
  4 HARMFUL queries   → blocked
  2 UNCERTAIN queries → held for review
```

---

## Pattern 2 — MCP02: HITL Authorization Gate

**OWASP Risk:** MCP02:2025 — Excessive Permissions & Scope Creep

**The problem:**
An agent granted write access uses it every time it's called — correctly
or not. In the telecom fleet domain, a write is a firmware push to a live
device: irreversible the moment it starts. A wrong version, a poisoned
device record claiming a release that was never shipped, or a reasoning
loop proposing the same bad update across many devices — without a human
checkpoint, any of these reaches production hardware before anyone notices.

**The pattern:**
```
Agent calls apply_firmware_update(device_id, target_version)
     ↓
Server queues it — returns approval_id, executes nothing
     ↓
Human reviews proposed action + agent reasoning at /pending-approvals
     ↓
Approve → mock write executes, logged as ACTION_EXECUTED
Reject  → write never happens, logged as HUMAN_DECISION
```

Read-only tools skip the gate entirely — only writes pause. The agent
keeps doing what it's good at: watching the fleet and proposing
remediation. Only a human decision unlocks the code path that reaches the
device API.

**What it prevents:**
- A wrong or attacker-influenced firmware version reaching a live device
- Fleet-wide batch mistakes (no second write executes without its own
  separate approval)
- Audits with no answer to "who authorized this change"

**Location:** `patterns/MCP02-hitl-gate/`

**Run it:**
```powershell
# Terminal 1
cd patterns/MCP02-hitl-gate
python server.py

# Terminal 2
python attack_demo.py    # See writes executing with no gate
python client.py         # Full agent + human approve/reject round trip
python test_mcp02.py     # Automated test suite
```

**Test result:**
```
Approval flow:       ✅ write executes only after human Approve
Rejection flow:       ✅ write blocked, result stays null after human Reject
Double-decision guard: ✅ a second decision on the same approval is rejected (400)
Results: 3/3 passed
```

---

## Quick Start — Run Both

```powershell
# Install dependencies (once)
pip install -r requirements.txt

# MCP05/06 — Probabilistic Triage Gate
cd patterns/MCP05-06-triage-gate
python server.py          # Terminal 1
python test_mcp0506.py    # Terminal 2

# MCP02 — HITL Authorization Gate
cd patterns/MCP02-hitl-gate
python server.py          # Terminal 1
python client.py          # Terminal 2
python test_mcp02.py      # Terminal 2
```

---

## How Group 2 Connects to Group 1

Group 2 doesn't replace Group 1 — it builds directly on top of it.

- **MCP02 reuses `session_store.py` from MCP08** rather than rolling its
  own audit log. Every `HITL_GATE` and `HUMAN_DECISION` event lands in the
  exact same append-only store Group 1 built, so a security team
  reconstructing an incident gets one timeline, not two.
- **MCP05/06 sits in front of the same agent flow MCP03 protects.** MCP03
  sanitizes content the agent already retrieved; MCP05/06 classifies
  intent before the agent even starts reasoning. Together they cover both
  directions: what the agent reads, and what the agent is about to do
  about it.
- **MCP01's "no credentials in context" guarantee still holds.** Adding
  active blocking and authorization doesn't change where credentials live
  — they're still fetched at execution time, after both gates have
  already let a request through.

Group 1 is the foundation that makes Group 2's logging and reasoning
trustworthy in the first place. Group 2 is the foundation that makes
Group 1's recorded decisions actually *mean* something — because now some
of those decisions are "blocked" and "rejected," not just "executed."

---

## What Group 3 Adds Next

Group 1 controls what reaches the agent and records what it does.
Group 2 actively blocks harmful intent and gates unauthorized writes.

Group 3 (Week 3) adds the perimeter around the connection itself:
- **MCP07** — AAuth agent identity & request signing: is the caller even
  who they claim to be, before any of the above gets a chance to run?
  Cryptographic Ed25519 identity and signed requests, not a bearer token.
- **MCP09** — Tool registry allowlist: is this MCP server itself
  authorized to exist, deny by default?
- **MCP10** — Context scoping: does this session's data stay isolated
  from every other session?

Group 1 answers "what did the agent see and do." Group 2 answers
"was that intent and that action allowed." Group 3 answers "was this
connection allowed to exist at all."

---

*Part of the mcp-security-patterns repo — 10 production security patterns
mapped to the OWASP MCP Top 10.*

*github.com/dnyandeobharambe/mcp-security-patterns*
