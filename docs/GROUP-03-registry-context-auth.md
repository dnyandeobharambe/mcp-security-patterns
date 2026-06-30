# Group 3 — Registry, Context & Authentication

**Patterns:** MCP07 (complete) · MCP09 · MCP10 (next)

**Theme:** The Perimeter Layer.

Group 1 controls what reaches the agent and records what it does. Group 2
actively blocks harmful intent and gates unauthorized writes. Both groups
assume the connection itself is legitimate — that the caller really is the
agent it claims to be, that the MCP server itself is one the fleet should
be talking to, that one session's data can't bleed into another's.

Group 3 stops assuming that. It sits at the perimeter, before any of
Group 1 or Group 2's logic gets a chance to run, and asks three questions
none of the earlier patterns ask:

- **Is the caller who it claims to be?** → **MCP07** replaces a bearer
  token (a string anyone can copy) with a signature (proof of possessing
  a private key that never leaves the agent).
- **Is this MCP server itself allowed to exist?** → **MCP09** enforces a
  tool registry allowlist, deny by default.
- **Does this session's data stay isolated from every other session?**
  → **MCP10** prevents cross-session and cross-tenant context leakage.

This document covers **MCP07**, the first pattern in the group, in full.
MCP09 and MCP10 are scoped below and will be documented the same way once
built.

---

## The Domain — IoT Device Fleet Management, Continued

Same fleet as every other pattern in this repo: 5,000+ field devices —
gateways, base station controllers, edge routers — reporting compliance
state continuously, with an agent calling `check_device_compliance` and
`apply_firmware_update` against that fleet.

MCP01 isolates the credential the *server* uses downstream to call the
device API. MCP02 gates the *write* itself behind human approval. Neither
one asks who's calling the *MCP server* in the first place. If an
attacker can replay a stolen bearer token, they reach MCP01's and MCP02's
machinery as a fully trusted caller — credential isolation and the HITL
gate are both working exactly as designed, for the wrong agent.

MCP07 closes that gap: before a request ever reaches `/tools/call`, the
server already knows — cryptographically, not by trusting a string —
which agent identity is making the call.

---

## Why These Three Belong Together

```
Connection arrives              ←  MCP07 Agent Identity & Request Signing
        ↓ signature verified
Is this server allowed to exist? ←  MCP09 Tool Registry Allowlist
        ↓ registered & permitted
Session data scoped              ←  MCP10 Context Scoping
        ↓ isolated from other sessions/tenants
Request reaches Group 1 / Group 2 logic
```

- MCP07 controls **who is allowed to make the call**
- MCP09 controls **what the call is allowed to reach**
- MCP10 controls **what data the call is allowed to see**

Implement only MCP07 and a correctly authenticated agent can still call
tools it was never meant to have access to, or read another tenant's
session state. Implement only MCP09 or MCP10 and a stolen bearer token
still walks straight through them as a trusted identity. Together, the
three close the connection-level perimeter the same way Group 2 closed
the proposal pipeline: identity, scope, and isolation, each independently
enforced.

---

## The Attack This Group Defends Against

**The impersonation chain:**

```
Step 1: Attacker captures a credential from a log, proxy, or APM trace
        (a bearer token — the entire identity, in one copyable string)
Step 2: Attacker replays it from any machine, at any time
Step 3: The server cannot distinguish attacker from legitimate agent
Step 4: Every downstream control — credential isolation, HITL gates,
        triage gates — now runs on behalf of the attacker, fully trusted
Step 5: Whatever those controls would have allowed the real agent to do,
        the attacker can now do too
```

**How MCP07 breaks this chain:**

```
Step 1: Attacker captures an entire signed request off the wire —
        headers and body, everything that was transmitted
Step 2: There is no static secret in the capture. Identity was never
        a string — it's a one-time-use signature, bound to that exact
        request's body and nonce
Step 3: Attacker replays the capture verbatim
        Nonce already recorded → REJECTED ← CHAIN BROKEN
Step 4: Attacker rewrites the body to escalate the action, keeping the
        stolen signature
        Signature no longer matches the new body → REJECTED ← CHAIN BROKEN
Step 5: Attacker cannot produce a new, valid signature over anything —
        doing that requires the private key, and the private key never
        left the legitimate agent's process
```

A captured request is not a reusable credential. It's a dead proof the
moment it's used once, and worthless if modified at all.

---

## Pattern 1 — MCP07: AAuth Agent Identity & Request Signing

**OWASP Risk:** MCP07:2025 — Insecure Credential & Identity Management

**The problem:**
A bearer token is a static secret sent on every request. It ends up in
request logs, APM traces, and reverse-proxy access logs as a matter of
course. Anyone who reads any one of those gets the entire credential —
and the server has no way to tell a replay from the legitimate agent,
because the token *is* the identity.

**The pattern:**
```
Agent generates an Ed25519 keypair — private key never leaves the agent
        ↓
Agent registers its public key with the server (stand-in for AAuth's
JWKS discovery)
        ↓
Every request is signed: method + path + agent_id + timestamp + nonce
+ body-digest, signed with the private key
        ↓
Server verifies: known agent_id → timestamp within ±120s → nonce not
already used → signature valid against the registered public key
        ↓
Verified → tool executes, response includes the authenticated agent_id
```

No `Authorization` header. No shared secret anywhere in the protocol.

**What it prevents:**
- A captured bearer token being replayed from a different machine
- A captured signed request being replayed verbatim (nonce reuse)
- A captured signed request being modified in flight to escalate to a
  different or more dangerous action (signature covers the body)
- An attacker forging any new request without the private key, period

**Location:** `patterns/MCP07-oauth-auth/`

**Run it:**
```powershell
# Terminal 1
cd patterns/MCP07-oauth-auth
python server.py

# Terminal 2
python attack_demo.py    # Bearer token replay succeeding vs. AAuth capture failing
python client.py         # Full agent identity + signed request round trip
python test_mcp07.py     # Automated test suite
python reset_registry.py # Clear registry/nonce state for a clean re-run
```

**Test result:**
```
Test 1: Valid signed request succeeds                                ✅ 200
Test 2: Unregistered agent identity is rejected                      ✅ 401
Test 3: Tampering with the body invalidates the signature            ✅ 401
Test 4: Replaying an already-used signed request is rejected         ✅ 401
Test 5: A bare bearer-style call with no AAuth headers is rejected    ✅ 401
Test 6: A stale timestamp outside the clock-skew window is rejected   ✅ 401
Results: 6/6 passed
```

What an attacker gains from a full request capture: one already-used,
now-dead proof.

---

## Coming Next — MCP09: Tool Registry Allowlist

**OWASP Risk:** MCP09:2025 — Rogue/Unverified MCP Servers

**The problem (to be implemented):** an agent will call whatever MCP
server it's pointed at. Nothing about MCP07's identity verification
stops a legitimate, correctly authenticated agent from being pointed at
a malicious or unregistered server. MCP09 enforces a deny-by-default
allowlist — only servers explicitly registered are reachable — and takes
MCP07-verified agent identity as an input to its authorization decision.

**Location (planned):** `patterns/MCP09-tool-registry/` — port 8009

---

## Coming Next — MCP10: Context Scoping

**OWASP Risk:** MCP10:2025 — Multi-Tenant Context Leakage

**The problem (to be implemented):** even with a verified identity and an
allowlisted server, nothing yet prevents one session's context — device
data, conversation history, intermediate reasoning — from leaking into
another session or another tenant's view. MCP10 scopes context storage
and retrieval so a session can only ever see its own data.

**Location (planned):** `patterns/MCP10-context-scoping/` — port 8010

---

## Quick Start — Run What's Built So Far

```powershell
# Install dependencies (once)
pip install -r requirements.txt

# MCP07 — AAuth Agent Identity & Request Signing
cd patterns/MCP07-oauth-auth
python server.py          # Terminal 1
python client.py          # Terminal 2
python test_mcp07.py      # Terminal 2
```

---

## How Group 3 Connects to Groups 1 & 2

Group 3 doesn't replace the earlier groups — it runs in front of them.

- **MCP07 establishes the identity that MCP02's audit trail records.**
  Once MCP09/MCP10 land, every `HITL_GATE` and `HUMAN_DECISION` event in
  the shared session store can be tied back to a cryptographically
  verified `agent_id`, not just a self-reported session ID.
- **MCP05/06's triage gate and MCP07's identity check are independent
  layers, like Group 1 and Group 2 already are.** A correctly identified
  agent can still send a harmful query; triage still has to catch it.
  A safe query from an unverified caller still has to fail identity
  first. Neither layer substitutes for the other.
- **MCP01's "no credentials in context" guarantee is unaffected and
  reinforced.** Credentials are still fetched at execution time — now
  that execution only happens after the caller's identity itself has
  been cryptographically verified, not just trusted because a request
  arrived.

Groups 1 and 2 answer "what did the agent see and do, and was that
intent and action allowed." Group 3 answers a question that has to be
settled before any of that: "was this connection allowed to exist at
all, and is it still who it claimed to be on every single request."

---

## What's Left in Group 3

- MCP07 — AAuth Agent Identity & Request Signing — ✅ complete, 6/6 tests passing
- MCP09 — Tool Registry Allowlist — not yet built
- MCP10 — Context Scoping — not yet built

---

*Part of the mcp-security-patterns repo — 10 production security patterns
mapped to the OWASP MCP Top 10.*

*github.com/dnyandeobharambe/mcp-security-patterns*
