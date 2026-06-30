# MCP09 — Tool Registry Allowlist

**OWASP MCP Risk:** MCP09:2025 — Rogue/Unverified MCP Servers & Tools

---

## The Domain

Same fleet as the rest of this repo: a telecom operator running 5,000+
field devices, with multiple agent roles calling the same MCP server —
a `compliance-agent` doing read-only audits, a `fleet-ops-agent`
scheduling firmware updates, a `fleet-admin-agent` with broader access
for incident response.

[MCP07](../MCP07-oauth-auth/) answers "is the caller who it claims to
be?" with a cryptographic identity. It does **not** answer a second
question: once identity is established, **what is that identity
actually allowed to reach?** A correctly authenticated `compliance-agent`
is still just a string match away from calling any tool the server
knows how to execute — including ones it was never provisioned for.

---

## The Attack

The MCP server exposes every tool it implements as one flat namespace.
Any caller that knows a tool's name can invoke it:

```
compliance-agent-001 -> check_compliance(D-1042)      # expected
compliance-agent-001 -> export_all_device_data()       # NOT expected
```

`export_all_device_data` is a **shadow tool** — it exists on the server
(maybe left over from an admin debugging script, maybe added for one
internal dashboard) but was never meant to be reachable by routine
fleet agents. Without a registry, "the tool exists" and "this caller
may use it" are the same check — which means they aren't checked at
all. A compliance agent that only ever needed two read-only endpoints
can call a bulk-export tool and exfiltrate the entire fleet's data in
one request, and the server has no concept of that being wrong.

**This is MCP09. An MCP server with no tool registry has no notion of
"this identity, this tool" — only "this tool exists, so it runs."**

---

## The Defense — Tool Registry, Deny by Default

Two structures, enforced before any tool handler runs:

```
TOOL_CATALOG       — every tool the server knows how to execute at all
ROLE_ALLOWLISTS     — per role, the subset of TOOL_CATALOG it may call
```

A tool call is authorized only if it clears three checks, in order:

```
1. tool_name is non-empty                         -> else 400
2. tool_name exists in TOOL_CATALOG                -> else 404
3. tool_name is in the caller's role's allowlist   -> else 403
```

```
compliance-agent     -> {check_compliance, get_device_status}
fleet-ops-agent       -> {check_compliance, get_device_status, apply_firmware_update}
fleet-admin-agent     -> {check_compliance, get_device_status, apply_firmware_update,
                          export_all_device_data, admin_reset_device}
```

Being in `TOOL_CATALOG` is necessary but not sufficient — the shadow
tool from the attack still exists in the catalog (it has to, for the
admin role that legitimately needs it), but a role not explicitly
allowlisted for it gets rejected exactly the same as if the tool name
were a typo. There is no implicit trust extended to "known tool name" —
only to an explicit `(role, tool)` pair.

---

## Attack Demo — Real Output

Run `attack_demo.py` — no server needed, it's self-contained:

```bash
python attack_demo.py
```

Actual console output:

```
⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️
VULNERABLE PATTERN — NO TOOL REGISTRY — DO NOT USE IN PRODUCTION
⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️

compliance-agent-001 was provisioned to do ONE thing: read-only compliance checks.
  check_compliance(D-1042) -> {'device_id': 'D-1042', 'compliance': 'NON_COMPLIANT'}

Nothing stops the same agent identity from calling a shadow tool it
was never meant to reach — the server has no concept of 'allowed for this role.'
  export_all_device_data() -> {'devices': [...], 'exported_count': 3}
  Entire fleet exfiltrated by a read-only compliance agent: 3 devices


✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅
WITH Tool Registry — MCP09 Pattern
✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅

compliance-agent-001's role allowlist:
  ['check_compliance', 'get_device_status']

Allowed call: check_compliance
  is_allowed(compliance-agent-001, check_compliance) -> True

Same agent identity attempts the shadow tool that exfiltrated the fleet in Part 1:
  is_allowed(compliance-agent-001, export_all_device_data) -> False
  Blocked by: deny-by-default role allowlist — tool exists, but not for this role

Same shadow tool reachable by the role it WAS provisioned for:
  is_allowed(fleet-admin-agent-001, export_all_device_data) -> True
  Explicit allowlist entry, not a blanket trust of 'known tool name'

An entirely unregistered tool name, attempted by any agent:
  is_known_tool(delete_everything) -> False
  Rejected before role checks even run — not in the catalog at all


============================================================
ATTACK SURFACE COMPARISON
============================================================

❌ No tool registry:
  - Agent can call any tool whose name it knows: YES
  - Shadow/deprecated tools reachable by any caller: YES
  - Role distinctions enforced anywhere: NO
  - Blast radius of one compromised agent identity: entire tool surface

✅ Tool registry allowlist (MCP09):
  - Tools in catalog: 5
  - Unknown tool names: rejected (404), before role checks run
  - Known tool, wrong role: rejected (403), explicit allowlist miss
  - Blast radius of one compromised agent identity: only that role's allowlist
============================================================
```

---

## Pattern Demo

```powershell
# Terminal 1 — start the secure MCP server
python server.py

# Terminal 2 — run the legitimate agent
python client.py

# Terminal 2 — verify every check (server must still be running)
python test_mcp09.py

# Terminal 2 — reset in-memory call log for a clean re-run
python reset_registry.py
```

`client.py` calls `compliance-agent-001`'s allowed tools successfully,
then attempts the same shadow tool the attack demo used to exfiltrate
data, and is rejected by the live server with `403`.

**Test result:**
```
Test 1: Allowed tool call succeeds                                  ✅ 200
Test 2: Unauthorized tool blocked (exists, wrong role)               ✅ 403
Test 3: Unknown tool blocked                                         ✅ 404
Test 4: Agent with a different role gets a different allowlist       ✅
Test 5: Empty tool name rejected                                     ✅ 400
Test 6: Registry returns the list of allowed tools for an agent      ✅ 200
Results: 6/6 passed
```

---

## How It Works

```
client.py (agent)                 server.py (MCP server)
     |                                  |
     |-- POST /tools/call ------------->|
     |   X-Agent-Id: compliance-agent-001
     |   {tool_name, params}            |-- tool_name empty?         -> 400
     |                                  |-- tool_name in catalog?    -> 404 if not
     |                                  |-- role allowlist contains  -> 403 if not
     |                                  |   tool_name?
     |                                  |-- execute handler
     |<- {status, result, agent_id} ----|
     |                                  |
     |-- GET /agents/{id}/allowed-tools->|
     |<- {role, allowed_tools} ---------|
```

---

## Key Code Pattern

```python
# tool_registry.py — deterministic allowlist enforcement, no LLM involved
def is_allowed(self, agent_id: str, tool_name: str) -> bool:
    role = self.get_role(agent_id)
    if role is None:
        return False
    return tool_name in ROLE_ALLOWLISTS.get(role, set())
```

```python
# server.py — three checks, in order, before any handler runs
if not request.tool_name:
    raise HTTPException(400, "tool_name is required")
if not registry.is_known_tool(request.tool_name):
    raise HTTPException(404, f"Tool '{request.tool_name}' not found")
if not registry.is_allowed(x_agent_id, request.tool_name):
    raise HTTPException(403, f"role not authorized for tool '{request.tool_name}'")
```

---

## Relationship to MCP07

MCP07 and MCP09 are independent layers, like every other pair of
patterns in this repo:

- A correctly identified agent (MCP07) can still be over-provisioned —
  MCP09 still has to restrict what it's allowed to reach.
- An agent that's authorized for a tool (MCP09) is still only as
  trustworthy as the identity check that put it there — MCP07 still
  has to verify that identity in the first place.

In production, `X-Agent-Id` here would come from an MCP07-verified
signature, not a plain header — this demo keeps identity simple so the
registry's authorization logic stays the focus.

---

## Files

- `tool_registry.py` — tool catalog, per-role allowlists, demo agent-to-role mapping
- `server.py` — MCP server enforcing the allowlist on every `/tools/call`
- `client.py` — agent calling allowed tools, then a blocked shadow tool
- `attack_demo.py` — no-registry shadow-tool exfiltration vs. registry-blocked attempt
- `test_mcp09.py` — verifies allowed/unauthorized/unknown/empty/per-role cases
- `reset_registry.py` — clears the call audit log for a fresh demo run

---

**An MCP server's tool surface is not automatically its authorization
surface. Without a registry, every tool is reachable by every caller —
"exists" and "allowed" collapse into the same check, which means
neither one is actually being checked.**
