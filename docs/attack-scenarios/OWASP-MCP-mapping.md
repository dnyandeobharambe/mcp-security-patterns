# OWASP MCP Top 10 — Attack Scenarios and Pattern Mapping

Reference: owasp.org/www-project-mcp-top-10 (Beta, 2025)

---

## MCP01 — Token Mismanagement & Secret Exposure
**Pattern:** [MCP01-credential-isolation](../../patterns/MCP01-credential-isolation/)

**Attack:** Credentials hardcoded in agent context, MCP config, or environment variables
passed to agent. Appear in LangSmith traces. Extractable via prompt injection.

**Real CVE:** CVE-2026-32211 — Azure MCP Server missing auth layer

**Defense:** Credentials fetched from Key Vault at execution time only. Never in agent context.

---

## MCP02 — Excessive Permissions & Scope Creep
**Pattern:** [MCP02-hitl-gate](../../patterns/MCP02-hitl-gate/)

**Attack:** Agent granted write access it doesn't need. Permissions accumulate over time.
Attacker exploits broad scope to exfiltrate or modify data.

**Defense:** Minimal permissions. HITL gate on all write operations.

---

## MCP03 — Tool Poisoning & Malicious Instructions
**Pattern:** [MCP03-content-sanitization](../../patterns/MCP03-content-sanitization/)

**Attack:** Hidden instructions embedded in tool responses, document content, or
database records. Agent reads data, processes as instructions, follows attacker commands.

**Attack success rate:** 84.2% with auto-approval enabled (research benchmark)

**Defense:** Sanitize all tool responses before returning to agent context.

---

## MCP04 — Software Supply Chain Attacks
**Pattern:** [MCP04-supply-chain](../../patterns/MCP04-supply-chain/)

**Attack:** Compromised MCP packages, typosquatted servers, fake official connectors.
First malicious MCP package landed September 2025.

**Defense:** Pin versions. Verify checksums. Hash tool descriptions at first run.

---

## MCP05/06 — Command Injection + Intent Flow Subversion
**Pattern:** [MCP05-06-triage-gate](../../patterns/MCP05-06-triage-gate/)

**Attack:** Agent constructs shell commands or API calls from untrusted input.
Attacker controls what the agent does by controlling what it reads.
43% of 2026 CVEs were shell injections.

**Defense:** Probabilistic Triage Gate — classify intent before agent processes.

---

## MCP07 — Insufficient Authentication & Authorization
**Pattern:** [MCP07-oauth-auth](../../patterns/MCP07-oauth-auth/)

**Attack:** MCP servers with no auth, or weak token validation.
38% of scanned MCP servers lack any authentication.

**Defense:** OAuth 2.1 with PKCE. Token validation on every request.

---

## MCP08 — Audit & Logging Deficiencies
**Pattern:** [MCP08-session-recording](../../patterns/MCP08-session-recording/)

**Attack:** No record of what agent did or why. Incident investigation impossible.
Compliance audit fails.

**Defense:** Full session recording — every decision, every tool call, replayable.

---

## MCP09 — Shadow MCP Servers
**Pattern:** [MCP09-tool-registry](../../patterns/MCP09-tool-registry/)

**Attack:** Unauthorized MCP servers spun up by developers outside security governance.
Agent discovers and connects to them dynamically. Attacker registers malicious server
that impersonates legitimate one.

**Defense:** Tool registry allowlist. Deny by default. Only pre-approved servers.

---

## MCP10 — Context Over-Sharing
**Pattern:** [MCP10-context-scoping](../../patterns/MCP10-context-scoping/)

**Attack:** Sensitive data from one user session leaks into another.
Shared context windows expose PII, credentials, or business data across users.

**Defense:** Per-session context isolation. Minimal context principle.

---

## Statistics

| Metric | Value | Source |
|---|---|---|
| CVEs filed against MCP in early 2026 | 30+ | Multiple researchers |
| Attack success rate with auto-approval | 84.2% | Security benchmark |
| MCP servers without authentication | 38% | Scan of 500+ servers |
| Average security score of MCP servers | 34/100 | Audit of 17 popular servers |
| Attack success with 5 connected servers | 78.3% | Palo Alto Unit 42 |
| CVEs that were shell injections | 43% | 2026 CVE data |
