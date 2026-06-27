# MCP Security Patterns

> **Production security patterns for MCP (Model Context Protocol) AI agents.**
> 10 working implementations mapped to the OWASP MCP Top 10.
> Prompt injection defense · Credential isolation · HITL governance · Session recording · OAuth 2.1 · Tool poisoning prevention.

[![OWASP MCP Top 10](https://img.shields.io/badge/OWASP-MCP%20Top%2010-red)](https://owasp.org/www-project-mcp-top-10/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue)](https://python.org)

---

## What This Is

A reference implementation for securing MCP servers and AI agent pipelines in enterprise environments.

Each pattern addresses one OWASP MCP Top 10 risk with:
- **Working attack demo** — showing exactly how the vulnerability gets exploited
- **Working defense** — production-ready Python implementation
- **Test file** — verify the pattern works in your environment

Not documentation. Not guidelines. Running code with attack demos.

---

## Why This Exists

MCP (Model Context Protocol) lets AI agents connect to real enterprise systems —
databases, ERP, email, patient records, billing systems. That power comes with risk.

**The numbers:**
- 12,520 MCP servers found exposed on the public internet (Censys scan, 2026)
- 38% of scanned MCP servers have zero authentication
- 84.2% of tool poisoning attacks succeed with auto-approval enabled
- 30+ CVEs filed against MCP implementations in early 2026
- NSA published formal MCP security guidance — May 2026

The core problem: **model-level guardrails are probabilistic. Security requires determinism.**

The same prompt can be refused on Monday and obliged on Tuesday.
You cannot draw a security boundary with a guardrail.
The boundary must live in the deterministic layer around the model — not inside it.

> Read [ARCHITECTURE.md](ARCHITECTURE.md) for the full explanation.

---

## OWASP MCP Top 10 Coverage

| Pattern | OWASP Risk | Week | Status |
|---|---|---|---|
| [MCP01 — Credential Isolation](patterns/MCP01-credential-isolation/) | Token Mismanagement & Secret Exposure | 1 | ✅ Complete |
| [MCP02 — HITL Authorization Gate](patterns/MCP02-hitl-gate/) | Excessive Permissions & Scope Creep | 2 | ✅ Complete |
| [MCP03 — Content Sanitization](patterns/MCP03-content-sanitization/) | Tool Poisoning & Malicious Instructions | 1 | ✅ Complete |
| [MCP04 — Supply Chain Verification](patterns/MCP04-supply-chain/) | Software Supply Chain Attacks | 4 | 🔄 Coming |
| [MCP05/06 — Probabilistic Triage Gate](patterns/MCP05-06-triage-gate/) | Prompt Injection + Intent Subversion | 2 | ✅ Complete |
| [MCP07 — OAuth 2.1 Authentication](patterns/MCP07-oauth-auth/) | Insufficient Authentication & Authorization | 3 | 🔄 Coming |
| [MCP08 — Session Recording & Replay](patterns/MCP08-session-recording/) | Audit & Logging Deficiencies | 1 | ✅ Complete |
| [MCP09 — Tool Registry Allowlist](patterns/MCP09-tool-registry/) | Shadow MCP Servers | 3 | 🔄 Coming |
| [MCP10 — Context Scoping](patterns/MCP10-context-scoping/) | Context Over-Sharing & PII Leakage | 3 | 🔄 Coming |
| [Full Stack Demo](examples/full-stack-demo/) | All ten patterns combined | 4 | 🔄 Coming |

---

## Pattern Groups

| Group | Patterns | Theme | Status |
|---|---|---|---|
| [Group 1 — Isolation, Sanitization & Recording](docs/GROUP-01-isolation-sanitization-recording.md) | MCP01, MCP03, MCP08 | Foundational defense layer — no LLM required | ✅ Complete |
| [Group 2 — Triage & Authorization](docs/GROUP-02-triage-authorization.md) | MCP05/06, MCP02 | Active blocking and human-in-the-loop control | ✅ Complete |
| [Group 3 — Registry, Context & Auth](docs/GROUP-03-registry-context-auth.md) | MCP09, MCP10, MCP07 | Who connects, what tools exist, what context is shared | 🔄 Week 3 |
| [Group 4 — Supply Chain & Full Stack](docs/GROUP-04-supply-chain-fullstack.md) | MCP04, Full Demo | Trust the software, see all patterns together | 🔄 Week 4 |

---

## Defense Architecture

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

Each layer is independent. Deploy one or all ten.
A jailbroken model that hits this pipeline cannot breach the perimeter.

---

## Quick Start

```bash
# Clone
git clone https://github.com/dnyandeobharambe/mcp-security-patterns
cd mcp-security-patterns

# Environment — Windows
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Environment — Mac/Linux
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Test Pattern 1 — Credential Isolation
cd patterns/MCP01-credential-isolation
python server.py          # Terminal 1 — start MCP server
python attack_demo.py     # Terminal 2 — see the vulnerability
python test_mcp01.py      # Terminal 2 — see the defense
```

---

## Pattern Structure

Every pattern follows the same format:

```
patterns/MCP0X-pattern-name/
├── README.md          # Attack scenario, defense explanation, how to run
├── server.py          # MCP server with the security pattern implemented
├── attack_demo.py     # Demonstrates the vulnerability WITHOUT the pattern
├── test_mcp0X.py      # Test file — run to verify the pattern works
└── client.py          # Agent client showing the pattern in action
```

---

## Key Concepts

**Prompt Injection** — malicious instructions hidden in content the agent retrieves.
Defended by MCP03 (content sanitization) and MCP05/06 (triage gate).

**Credential Isolation** — API keys and tokens must never appear in agent context.
Defended by MCP01. Prevents credential extraction via prompt injection or log access.

**HITL Governance (Human-in-the-Loop)** — agent proposes, human authorizes.
Write operations on enterprise systems require explicit human approval.
Defended by MCP02.

**Tool Poisoning** — malicious MCP server or tool definition hijacks agent behavior.
Defended by MCP03, MCP09 (tool registry), MCP04 (supply chain).

**Shadow MCP Servers** — unauthorized MCP deployments outside security governance.
Defended by MCP09 (allowlist — deny by default).

**Context Over-Sharing** — PII from one session leaks into another.
Defended by MCP10 (per-session isolation).

**Session Recording** — every agent decision captured for forensic investigation.
Implemented by MCP08 (immutable append-only audit trail).

---

## Stack

- **Python 3.11+**
- **FastAPI** — MCP server implementation
- **LangGraph** — agent orchestration and HITL workflows
- **LangSmith** — observability and reasoning trace capture
- **Azure Key Vault** — credential management (mock included for local dev)
- **OAuth 2.1 / PKCE** — MCP server authentication (MCP07)

---

## Related Resources

- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NSA MCP Security Guidance](https://www.nsa.gov) — May 2026
- [MCP Security Specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/security)
- [MITRE ATLAS — AI Attack Techniques](https://atlas.mitre.org)

---

## Related Work

**OWASP LLM Top 10 Implementations**
Working vulnerable and mitigated implementations for OWASP LLM Top 10 risks.
github.com/dnyandeobharambe/owasp-llm-security

Together these repos cover both OWASP AI security frameworks:
- OWASP LLM Top 10 — risks in LLM applications
- OWASP MCP Top 10 — risks in AI agent protocols
  
---

## Author

**Danny Bharambe** — AI Security Architect | Enterprise AI | MCP Security

[linkedin.com/in/dnyandeo](https://linkedin.com/in/dnyandeo) · [github.com/dnyandeobharambe](https://github.com/dnyandeobharambe)

---

## License

MIT — use freely, credit appreciated.

---

## Topics

`mcp` `model-context-protocol` `ai-security` `llm-security` `prompt-injection`
`owasp` `enterprise-ai` `agentic-ai` `hitl` `credential-isolation`
`tool-poisoning` `ai-agents` `langraph` `fastapi` `python`

