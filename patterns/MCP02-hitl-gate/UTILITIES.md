# MCP02 — Utility Scripts

These scripts are not part of the core HITL gate pattern (`server.py` is).
They exist to drive and reset the demo without writing one-off curl or
`Invoke-RestMethod` commands every time you want to test something.

| Script | Purpose | Use it when |
|---|---|---|
| `submit_action.py` | Queue a single write operation | You want to push one specific device/version through the gate |
| `reset_approvals.py` | Clear all approval state | You want a clean slate between demo runs, without restarting the server |
| `client.py` | Run the full agent + human round trip | You want to see both the approve and reject paths end-to-end in one run |

---

## submit_action.py

**Purpose:** Submits a single `apply_firmware_update` write request to the
running MCP02 server and prints the `approval_id` plus the URL to review it.

**When to use it:** Step 2 of the demo loop, when you want to control
exactly which device, target version, and reasoning get queued — for
example, to deliberately submit a suspicious version and watch it land in
`/pending-approvals` for review.

```bash
python submit_action.py --device D-1043 --version 9.9.9 --reason "Suspicious target version"
```

This only *queues* the write. Nothing executes until a human (you, in the
browser, or via `decide`) approves it.

---

## reset_approvals.py

**Purpose:** Calls `DELETE /approvals/reset` on the server, clearing every
pending and already-decided approval from memory.

**When to use it:** Step 4 of the demo loop — after you've approved or
rejected an action and want to run through the flow again without
restarting `server.py` (which would also lose the session log).

```bash
python reset_approvals.py
```

---

## client.py

**Purpose:** Not a lightweight utility like the two above — this is the
full agent-side demonstration. It proposes two write operations, plays the
role of a human reviewer deciding each one (clearly labeled `AGENT:` vs
`HUMAN:` in the output), and prints the final state of both: one executed,
one rejected.

**When to use it:** When you want to see the entire round trip — proposal,
queueing, human decision, execution or block — in a single run, without
opening a browser or calling `submit_action.py` and the approval page
separately.

```bash
python client.py
```

---

## The Demo Flow These Scripts Support

```
Step 1: python server.py
Step 2: python submit_action.py   (or python client.py for the full round trip)
Step 3: Interact with the browser at /pending-approvals, or via the API
Step 4: python reset_approvals.py
Step 5: Repeat from Step 2
```

See [README.md](README.md) for the full attack scenario, defense, and domain context.
