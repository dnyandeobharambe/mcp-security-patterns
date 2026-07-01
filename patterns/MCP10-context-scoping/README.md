# MCP10 — Context Scoping

**OWASP MCP Risk:** MCP10:2025 — Cross-Session/Cross-Tenant Context Leakage

---

## The Domain

Same fleet as the rest of this repo, now serving more than one customer:
`acme-telecom` and `globex-corp` are separate tenants of the same IoT
device management platform, each running their own agent sessions
against the same MCP server to check compliance and fetch device data.

[MCP07](../MCP07-oauth-auth/) answers "is the caller who it claims to
be?" and [MCP09](../MCP09-tool-registry/) answers "what is that identity
allowed to call?" Neither one answers a third question: once a session
exists and starts accumulating context — fetched device data,
conversation state — **who else can read it?** A `session_id` is just a
string. If the server treats "presents a session_id" as "owns that
session's context," any caller who obtains one — by guessing, by log
exposure, by a shared/global store — reads whatever that session holds,
regardless of which tenant it belongs to.

---

## The Attack

A naive context store keeps session state in one shared structure with
no tenant partitioning. Session IDs are generated, but nothing ever
checks *whose* they are:

```
acme-session-1  -> fetches acme-telecom's device data
globex-session-1 -> reads "its own" context ... and gets acme-telecom's data
```

Nothing about this requires an attacker to guess anything — the two
sessions were never actually isolated from each other. `globex-corp`
opened its own, entirely unrelated session and still received another
tenant's fleet data, because the store had no concept of "this context
belongs to this tenant."

**This is MCP10. An MCP server with no context scoping has no notion of
"this session, this tenant" — only "here is context, take it."**

---

## The Defense — Scope Every Session by session_id + tenant_id

One structure, checked before any context read or write:

```
ContextStore — session_id -> { tenant_id, data, expires_at }
```

A context operation is authorized only if it clears two checks, in order:

```
1. session_id exists and has not expired   -> else 404
2. presented tenant_id matches session's   -> else 403
   owning tenant_id
```

```
acme-telecom's session   -> only acme-telecom's tenant_id can read/write it
globex-corp's session    -> only globex-corp's tenant_id can read/write it
```

A `session_id` alone is never sufficient — it has to be paired with the
tenant_id the session was created under. A session that outlives its TTL
is deleted the moment it's looked up, so a leaked `session_id` has a
hard expiry instead of being valid forever.

---

## Attack Demo — Real Output

Run `attack_demo.py` — no server needed, it's self-contained:

```bash
python attack_demo.py
```

Actual console output:

```
⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️
VULNERABLE PATTERN — NO CONTEXT SCOPING — DO NOT USE IN PRODUCTION
⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️

acme-telecom opens an agent session and fetches its fleet's device data.
  session=acme-session-1 fetched -> {'tenant_id': 'acme-telecom', 'devices': [...]}

globex-corp opens a completely unrelated agent session moments later
and reads what it believes is its own fresh context...
  session=globex-session-1 context read -> {'devices': [{'device_id': 'D-1042', ... 'owner': 'acme-telecom'}, ...]}
  globex-corp just received acme-telecom's device data — no session_id/
  tenant_id check ever ran, so the two sessions shared one context


✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅
WITH Context Scoping — MCP10 Pattern
✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅

acme-telecom's session: sess-567cd6c271ed
globex-corp's session:  sess-9f9d5d6c744d

acme-telecom's agent fetches its device data into ITS OWN session context:
  write_context(sess-567cd6c271ed, ...) stored under tenant 'acme-telecom'

globex-corp's agent, presenting its OWN tenant_id, reads its OWN session:
  read_context(sess-9f9d5d6c744d) -> {}
  Empty — globex-corp never wrote anything to its own session

Attacker with a stolen/guessed acme-telecom session_id, presenting
globex-corp's tenant_id, tries to read acme-telecom's session directly:
  session 'sess-567cd6c271ed' belongs to tenant 'acme-telecom'
  request presented tenant 'globex-corp' -> blocked: True
  Rejected — session_id alone was never sufficient, tenant_id must match too


============================================================
ATTACK SURFACE COMPARISON
============================================================

❌ No context scoping:
  - Sessions share one undifferentiated context store: YES
  - A session_id alone treated as proof of ownership: YES
  - Cross-tenant data exposure via context read: YES
  - Blast radius of one leaked session_id: every tenant's context

✅ Context scoping (MCP10):
  - Every session keyed by session_id AND its owning tenant_id
  - Unknown/expired session_id: rejected (404), before tenant check runs
  - Known session, wrong tenant_id: rejected (403), explicit mismatch
  - Blast radius of one leaked session_id: that session's own context only
============================================================
```

---

## Pattern Demo

```powershell
# Terminal 1 — start the secure MCP server
python server.py

# Terminal 2 — run the legitimate two-tenant agent demo
python client.py

# Terminal 2 — verify every check (server must still be running)
python test_mcp10.py

# Terminal 2 — reset in-memory session state for a clean re-run
python reset_context.py
```

`client.py` has `acme-telecom` fetch and read its own session context,
has `globex-corp` read its own (separate, empty) session, then attempts
a cross-tenant read of `acme-telecom`'s `session_id` and is rejected by
the live server with `403`.

**Test result:**
```
Test 1: Session reads its own context successfully                   ✅ 200
Test 2: Different session cannot read another session's context      ✅
Test 3: Cross-tenant access blocked                                  ✅ 403
Test 4: Expired context returns 404                                  ✅ 404
Test 5: Writing to context succeeds for correct tenant                ✅ 200
Test 6: Context reset clears data correctly                           ✅
Results: 6/6 passed
```

---

## How It Works

```
client.py (agent)                 server.py (MCP server)
     |                                  |
     |-- POST /sessions --------------->|
     |   {tenant_id, ttl_seconds}       |-- create session, tie to tenant_id
     |<- {session_id, tenant_id} -------|
     |                                  |
     |-- GET /context/{session_id} ---->|
     |   X-Tenant-Id: <tenant_id>       |-- session known & not expired? -> 404 if not
     |                                  |-- X-Tenant-Id == session's tenant? -> 403 if not
     |<- {session_id, tenant_id, context}
     |                                  |
     |-- POST /context/{id}/write ----->|
     |   X-Tenant-Id, {data}            |-- same two checks, then merge into session.data
     |<- {status: written} -------------|
```

---

## Key Code Pattern

```python
# context_scope.py — deterministic scoping enforcement, no LLM involved
def session_status(self, session_id: str) -> str:
    session = self._sessions.get(session_id)
    if session is None:
        return "not_found"
    if self._is_expired(session):
        del self._sessions[session_id]
        return "expired"
    return "ok"
```

```python
# server.py — two checks, in order, before any context read/write runs
status = store.session_status(session_id)
if status == "not_found":
    raise HTTPException(404, f"Session '{session_id}' not found")
if status == "expired":
    raise HTTPException(404, f"Session '{session_id}' has expired")
if not tenant_id or tenant_id != store.get_tenant(session_id):
    raise HTTPException(403, "tenant_id does not match session owner")
```

---

## Relationship to MCP07 and MCP09

MCP07, MCP09, and MCP10 stack as independent layers, like every other
pair of patterns in this repo:

- A correctly identified agent (MCP07) with a correctly restricted tool
  surface (MCP09) can still read another tenant's context if the server
  doesn't scope sessions — MCP10 closes that gap.
- MCP10's tenant_id would, in production, come from the same verified
  identity MCP07 establishes — this demo accepts it as a plain header so
  the scoping logic in `context_scope.py` stays the focus.

---

## Files

- `context_scope.py` — session context store, session+tenant scoping, TTL expiry
- `server.py` — MCP server enforcing scoping on every context read/write
- `client.py` — two tenants, each with their own session, plus a blocked cross-tenant read
- `attack_demo.py` — no-scoping cross-tenant leak vs. scoped-and-blocked attempt
- `test_mcp10.py` — verifies own-session/cross-session/cross-tenant/expiry/write/reset cases
- `reset_context.py` — clears all session context for a fresh demo run

---

**An MCP server's session store is not automatically tenant-isolated.
Without explicit scoping, a session_id is treated as proof of ownership
by itself — which means any context, from any tenant, is one guessed or
leaked session_id away from being read by someone else entirely.**
