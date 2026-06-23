# MCP08 — Session Recording & Replay

**OWASP MCP Risk:** MCP08:2025 — Audit & Logging Deficiencies

---

## The Problem

Most MCP clients provide minimal logging. You know a tool was called.
You don't know why the agent decided to call it.

When something goes wrong — wrong action taken, security incident,
compliance audit — you need to answer:

- What did the agent reason?
- What tool did it call and with what parameters?
- What came back from the tool?
- What decision did it make based on that?
- Could it have been manipulated by content in the tool response?

Without session recording, you cannot answer any of these questions.

---

## The Defense — Full Session Recording

Every agent decision is captured:
- The reasoning step that led to the tool call
- The exact tool called and parameters sent
- The exact response received
- The next decision made based on that response
- Any human authorization decisions
- The final action taken

This creates a complete forensic record — rewindable to any point.

---

## What Gets Recorded

```
Session: sess-abc123
├── Step 1: Agent reasoning
│   └── "Device D-1042 needs compliance check"
├── Step 2: Tool call
│   ├── tool: check_device_compliance
│   ├── params: {"device_id": "D-1042"}
│   └── timestamp: 2026-06-18T22:00:01Z
├── Step 3: Tool response
│   ├── compliance_status: NON_COMPLIANT
│   ├── firmware_current: 2.3.1
│   └── firmware_required: 2.4.0
├── Step 4: Agent reasoning
│   └── "Device non-compliant. Recommend firmware update."
├── Step 5: HITL gate
│   ├── proposed_action: firmware_update D-1042 to 2.4.0
│   ├── human_reviewer: ops-team@company.com
│   └── decision: APPROVED at 2026-06-18T22:01:30Z
└── Step 6: Action executed
    └── firmware_update_job_id: job-xyz-789
```

---

## Replay

Run `replay.py session-id` to reconstruct any session:

```bash
python replay.py sess-abc123
```

Shows every step in sequence — what the agent saw, what it decided,
what a human authorized. Complete forensic reconstruction.

---

## How to Run

```bash
# Terminal 1 — start the recording MCP server
python server.py

# Terminal 2 — run agent session
python client.py

# Replay a specific session
python replay.py <session-id>
```

---

## Files

- `server.py` — MCP server with session recording
- `client.py` — Agent that generates a recordable session
- `replay.py` — Replay any session from the log
- `session_store.py` — Session storage (file-based, swap for DB in production)
