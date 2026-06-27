# MCP02 — HITL Authorization Gate

**OWASP MCP Risk:** MCP02:2025 — Excessive Permissions & Scope Creep

---

## The Domain — Enterprise IoT Fleet Management at Telecom Scale

A telecom operator runs 5,000+ field devices — gateways, base station
controllers, edge routers — that report compliance state continuously over
MQTT. Each device has a minimum firmware version policy. Devices that fall
behind are non-compliant, and non-compliance is a security and regulatory
problem, not just a maintenance one.

An AI agent watches this fleet. It consumes the MQTT compliance stream,
identifies devices running firmware below the required version, and
proposes a remediation action: push a firmware update to a specific device.

That proposal is the agent's entire job. It reasons about *which* device
needs *which* update and *why*. It does not get to decide that the update
actually happens — because a firmware push is not a read, it's a write,
and at telecom scale, writes are irreversible:

- Once a device starts flashing new firmware, there is no rollback button.
- A bad push to a live base station controller takes a cell site offline.
- A bad push at scale (the agent loops, or proposes the same bad version to
  many devices) is a fleet-wide outage, not a single-device incident.

This is exactly the kind of action that must never execute on the agent's
authority alone. That's what the HITL gate exists to enforce.

---

## The Attack — What Happens Without the Gate

An agent is granted write access to perform its job — push a firmware
update, modify a compliance record, schedule a remediation job. Once
granted, that permission is used on every call, with no human checkpoint:

```
Agent decides: "Update D-1043 firmware to 9.9.9"
     |
     v
Tool executes immediately — no review, no approval, no audit trail
```

The agent might be wrong. "9.9.9" might not correspond to any firmware
release the vendor ever shipped — it could be attacker-controlled content
that found its way into the agent's context via a poisoned device record
or compliance report. Either way, by the time anyone notices, the write
already happened: a live device in the field is now running unknown code,
or bricked outright.

**This is MCP02.** Permission, once granted to an agent, gets used —
correctly or not — every single time, with no point where a human could
have caught the mistake before it reached production hardware.

---

## The Defense — Human-in-the-Loop Gate

Write operations never execute inline. They are queued, surfaced to a
human with full context, and only execute after an explicit approve
decision:

```
Agent calls apply_firmware_update(device_id, target_version)
     |
     v
Server pauses — creates a pending approval, returns approval_id to agent
     |
     v
Human opens /pending-approvals — sees proposed action + agent reasoning
     |
     +-- Approve -> mock write executes, logged as ACTION_EXECUTED
     +-- Reject  -> write never executes, logged as HUMAN_DECISION
```

Read-only tools (`check_device_compliance`) skip the gate entirely — only
writes pause. The agent keeps doing what it's good at: continuously
watching the fleet and proposing remediation. The decision to actually
touch a production device is deterministic Python plus a human, never the
agent alone. Every decision is appended to the MCP08 session store, so who
approved what, and why, is always reconstructable.

---

## Real Production Consequences

What goes wrong at telecom scale when there's no gate:

- **A single bad push bricks a live base station controller** during peak
  traffic hours — an outage, an SLA breach, and an emergency field dispatch
  to a cell site that could have been a five-second "Reject" click.
- **An agent reasoning loop proposes the same update to 200 devices** in a
  batch sweep before anyone notices — what should have been one mistake is
  now a fleet-wide incident.
- **Attacker-controlled content reaches the agent's context** (a poisoned
  compliance report, a spoofed MQTT payload) and the agent proposes a
  firmware version that was never actually released — and it gets pushed
  to hardware before a human ever sees it.
- **A regulatory audit asks "who authorized this firmware change"** and
  there is no answer, because the agent acted alone and nothing recorded
  a human decision.
- **An on-call engineer is paged at 2am** for a device that's down — and
  has no way to tell whether a human ever approved the change that broke it.

Every one of these is the same root cause: a write operation that executed
on the agent's authority instead of a human's.

---

## Attack Demo

Run `attack_demo.py` to see write requests executing immediately with no
gate, compared against the same requests queued for approval:

```bash
python attack_demo.py
```

---

## Pattern Demo — How to Run

```bash
# Terminal 1 — start the HITL gate server
python server.py

# Terminal 2 — queue a write operation with the utility script
python submit_action.py --device D-1043 --version 9.9.9 --reason "Suspicious target version"
# Prints an approval_id and the URL to review it

# Open the approval page in a browser and click Approve or Reject yourself
# http://localhost:8002/pending-approvals
```

Or skip the browser and run the agent client, which proposes two writes
and shows the full approve/reject round trip end to end:

```bash
python client.py
```

Or run the full automated test suite (approval, rejection, double-decision):

```bash
python test_mcp02.py
```

### Standard Demo Loop

Run this loop as many times as you like — `reset_approvals.py` clears the
in-memory queue so each pass starts clean, without restarting the server:

```
Step 1: python server.py
Step 2: python submit_action.py  (or client.py)
Step 3: Interact with the browser at /pending-approvals, or via the API
Step 4: python reset_approvals.py
Step 5: Repeat from Step 2
```

---

## Key Code Pattern

```python
# server.py — write tools never execute inline
if request.tool_name in WRITE_TOOLS:
    approval_id = queue_for_approval(request)   # returns immediately, nothing runs
    return {"status": "pending_approval", "approval_id": approval_id}

# Only the human's decision can trigger execution
@app.post("/approvals/{approval_id}/decide")
async def decide_approval(approval_id: str, decision: str = Form(...)):
    if decision == "approve":
        execute_write(approval)   # the only path that reaches the device API
```

---

## Five Questions a Compliance Team Can Now Answer

1. **Which devices had a write operation proposed against them, and when?**
   Every `apply_firmware_update` proposal is logged as a `HITL_GATE` event
   the moment the agent calls it — before anything executes.

2. **Who approved or rejected each firmware push, and on what reasoning?**
   Every decision is logged as a `HUMAN_DECISION` event with the reviewer's
   identity, the decision, and the agent's original reasoning attached.

3. **Did any agent-proposed action ever execute without explicit human
   sign-off?** No — `execute_write()` is only reachable from the approve
   branch of `/approvals/{id}/decide`. There is no code path from agent
   proposal straight to device API.

4. **What did the agent believe before a human made the call?** The
   `agent_reasoning` field is captured and shown on the approval page and
   in the audit log — the human decision is informed, not blind.

5. **Can we prove, for audit or regulatory purposes, that no firmware
   update reached a device without authorization?** Yes — the MCP08
   session store is append-only. Replay any session and the full sequence
   (proposal → human review → decision → execution) is reconstructable.

---

## Files

- `server.py` — MCP server with HITL gate, HTML approval page, and approve/reject endpoints
- `client.py` — Agent that proposes a write operation and shows the full approval/rejection round trip
- `submit_action.py` — Utility script to queue a single write operation from the command line
- `reset_approvals.py` — Utility script to clear pending approval state for a fresh demo run
- `attack_demo.py` — Shows write operations executing WITHOUT the gate
- `test_mcp02.py` — Tests the approval flow, the rejection flow, and double-decision rejection
- `README.md` — This file

Reuses `session_store.py` from [MCP08-session-recording](../MCP08-session-recording/) —
every HITL gate event and human decision is appended to the same audit log.
