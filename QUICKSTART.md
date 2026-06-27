# Quickstart — 5 Minutes

For CISOs, CTOs, and architects who need the shape of this repo, not the code.

---

## The Problem

AI agents now connect directly to enterprise systems — databases, ERP,
device fleets, email. Traditional security assumes every component behaves
the same way every time. LLMs don't — the same input can be refused once
and obeyed the next. You cannot put a security boundary inside something
that isn't deterministic.

---

## The Solution

Put the security boundary *around* the model, in plain deterministic code,
not inside it. Every pattern in this repo is one link in that boundary:

```
Incoming request
      ↓
[MCP05/06] Probabilistic Triage Gate     — harmful query? block it
      ↓ safe
[MCP07]    OAuth 2.1 token validation    — authenticated caller?
      ↓ authenticated
[MCP09]    Tool registry allowlist       — approved tool?
      ↓ approved
[MCP04]    Supply chain verification     — trusted package?
      ↓ verified
[MCP03]    Content sanitization          — clean input? no injection?
      ↓ clean
           MCP Server executes tool
      ↓
[MCP01]    Credential from Key Vault     — injected at execution, never in context
      ↓
[MCP10]    Context scoped                — no cross-session PII leakage
      ↓
           Tool result returned
      ↓
[MCP03]    Response sanitization         — injection in tool output? block it
      ↓ clean
[MCP02]    HITL authorization gate       — write operation? human approves first
      ↓ approved
[MCP08]    Immutable session recording   — every decision logged, replayable
      ↓
           Action executes
```

The model can reason about anything. It cannot act without passing through
this stack.

---

## The Patterns

| Pattern | What It Prevents | Status |
|---|---|---|
| MCP01 — Credential Isolation | Credentials leaking into agent context, logs, or traces | ✅ Complete |
| MCP02 — HITL Authorization Gate | Write operations executing without human approval | ✅ Complete |
| MCP03 — Content Sanitization | Hidden instructions in retrieved content hijacking the agent | ✅ Complete |
| MCP04 — Supply Chain Verification | Compromised or typosquatted MCP packages | 🔄 Coming |
| MCP05/06 — Probabilistic Triage Gate | Harmful queries reaching the agent's reasoning at all | ✅ Complete |
| MCP07 — OAuth 2.1 Authentication | Unauthenticated callers reaching an MCP server | 🔄 Coming |
| MCP08 — Session Recording & Replay | Incidents nobody can reconstruct or explain | ✅ Complete |
| MCP09 — Tool Registry Allowlist | Unauthorized "shadow" MCP servers being trusted | 🔄 Coming |
| MCP10 — Context Scoping | PII or data leaking across user sessions | 🔄 Coming |
| Full Stack Demo | Shows all ten patterns running together | 🔄 Coming |

---

## Week 1 — Run It in 5 Minutes

See a credential leak into logs:

```bash
cd patterns/MCP01-credential-isolation
python server.py
python attack_demo.py
```

Now see the fix — same agent, no credential ever appears:

```bash
cd patterns/MCP01-credential-isolation
python server.py
python client.py
```

---

## Week 2 — See HITL in Action

Submit a write operation and approve it yourself in the browser:

```bash
cd patterns/MCP02-hitl-gate
python server.py
python submit_action.py
```

Open `http://localhost:8002/pending-approvals` and click **Approve**.
Nothing executed until you clicked it.

---

## The Philosophy

**The LLM reasons. The deterministic layer decides.**

---

## Links

- Full architecture: [ARCHITECTURE.md](ARCHITECTURE.md)
- Pattern groups: [docs/GROUP-01-isolation-sanitization-recording.md](docs/GROUP-01-isolation-sanitization-recording.md) · [docs/GROUP-02-triage-authorization.md](docs/GROUP-02-triage-authorization.md)
- Attack scenarios: [docs/attack-scenarios/OWASP-MCP-mapping.md](docs/attack-scenarios/OWASP-MCP-mapping.md)
