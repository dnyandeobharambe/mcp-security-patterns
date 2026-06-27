"""
MCP02 — HITL Authorization Gate Pattern
-------------------------------------------
Every write operation pauses for human approval before it executes.
The agent proposes the action. A human disposes of it.

OWASP MCP Risk: MCP02:2025 - Excessive Permissions & Scope Creep
"""

import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict
from fastapi import FastAPI, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
import uvicorn

# Reuse the immutable session log from MCP08 — every HITL decision is audited
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "MCP08-session-recording"))
from session_store import SessionStore, EventType

app = FastAPI(title="Secure MCP Server — MCP02 HITL Gate")
store = SessionStore()

# Tools that mutate state — these always require human approval
WRITE_TOOLS = {"apply_firmware_update"}

# In-memory pending-approval queue. Swap for a DB table in production.
PENDING_APPROVALS: Dict[str, Dict[str, Any]] = {}


class ToolRequest(BaseModel):
    tool_name: str
    params: Dict[str, Any]
    session_id: str
    step: int = 1
    agent_reasoning: str = ""


def mock_apply_firmware_update(device_id: str, target_version: str) -> Dict[str, Any]:
    """Mock enterprise device API call. Only ever reached after human approval."""
    return {
        "device_id": device_id,
        "job_id": f"job-{uuid.uuid4().hex[:8]}",
        "target_version": target_version,
        "status": "update_scheduled"
    }


def mock_check_device_compliance(device_id: str) -> Dict[str, Any]:
    mock_devices = {
        "D-1042": {"compliance": "NON_COMPLIANT", "firmware": "2.3.1", "required": "2.4.0"},
        "D-1043": {"compliance": "COMPLIANT", "firmware": "2.4.1", "required": "2.4.0"},
    }
    return {"device_id": device_id, **mock_devices.get(device_id, {"error": "device not found"})}


@app.post("/tools/call")
async def call_tool(request: ToolRequest):
    """
    Read-only tools execute immediately.
    Write tools are queued for human approval — never executed inline.
    """

    if request.tool_name not in WRITE_TOOLS:
        if request.tool_name == "check_device_compliance":
            result = mock_check_device_compliance(request.params.get("device_id"))
            return {"status": "executed", "result": result}
        return {"error": f"Tool '{request.tool_name}' not found"}

    # ─── HITL GATE — write operation paused for human approval ───
    approval_id = str(uuid.uuid4())
    approval = {
        "approval_id": approval_id,
        "session_id": request.session_id,
        "tool_name": request.tool_name,
        "params": request.params,
        "agent_reasoning": request.agent_reasoning,
        "status": "pending",
        "created_at": datetime.utcnow().isoformat(),
        "decided_at": None,
        "decided_by": None,
        "result": None
    }
    PENDING_APPROVALS[approval_id] = approval

    store.log_event(
        session_id=request.session_id,
        event_type=EventType.HITL_GATE,
        data={
            "approval_id": approval_id,
            "proposed_action": f"{request.tool_name}({request.params})",
            "agent_reasoning": request.agent_reasoning,
            "reviewer": "pending"
        },
        step=request.step
    )

    print(f"\n[HITL Gate] Write operation paused for approval: {approval_id}")
    print(f"  Tool: {request.tool_name}  Params: {request.params}")
    print(f"  Review at: http://localhost:8002/pending-approvals\n")

    return {
        "status": "pending_approval",
        "approval_id": approval_id,
        "session_id": request.session_id,
        "message": "Write operation requires human approval before executing."
    }


@app.get("/approvals/{approval_id}")
async def get_approval(approval_id: str):
    """Poll the outcome of a pending approval — used by the agent and tests."""
    approval = PENDING_APPROVALS.get(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="approval not found")
    return approval


@app.delete("/approvals/reset")
async def reset_approvals():
    """Clear all in-memory approval state — ready for a fresh demo run."""
    count = len(PENDING_APPROVALS)
    PENDING_APPROVALS.clear()
    print(f"[HITL Gate] Reset — cleared {count} approval(s)")
    return {"cleared": count, "message": "Ready for new demo"}


@app.get("/pending-approvals", response_class=HTMLResponse)
async def pending_approvals_page():
    """Simple HTML approval page — no external UI framework."""
    pending = [a for a in PENDING_APPROVALS.values() if a["status"] == "pending"]

    cards = ""
    for a in pending:
        cards += f"""
        <div class="card">
          <h3>{a['tool_name']}</h3>
          <p><b>Params:</b> {a['params']}</p>
          <p><b>Agent reasoning:</b> {a['agent_reasoning'] or 'No reasoning provided'}</p>
          <p><b>Approval ID:</b> {a['approval_id']}</p>
          <form method="post" action="/approvals/{a['approval_id']}/decide" style="display:inline">
            <input type="hidden" name="decision" value="approve">
            <button type="submit" style="background:#2e7d32;color:white;">Approve</button>
          </form>
          <form method="post" action="/approvals/{a['approval_id']}/decide" style="display:inline">
            <input type="hidden" name="decision" value="reject">
            <button type="submit" style="background:#c62828;color:white;">Reject</button>
          </form>
        </div>
        <hr>
        """

    if not cards:
        cards = "<p>No pending approvals.</p>"

    html = f"""
    <html>
    <head><title>MCP02 — Pending Approvals</title></head>
    <body style="font-family: sans-serif; max-width: 700px; margin: 40px auto;">
      <h1>Pending Write Approvals</h1>
      {cards}
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.post("/approvals/{approval_id}/decide")
async def decide_approval(
    approval_id: str,
    decision: str = Form(...),
    reviewer: str = Form("ops-team@company.com")
):
    """Hit by the Approve/Reject buttons on the HTML page (or a test client)."""
    approval = PENDING_APPROVALS.get(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="approval not found")
    if approval["status"] != "pending":
        raise HTTPException(status_code=400, detail=f"approval already {approval['status']}")

    decision = decision.lower()
    if decision not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="decision must be 'approve' or 'reject'")

    approval["decided_at"] = datetime.utcnow().isoformat()
    approval["decided_by"] = reviewer

    store.log_event(
        session_id=approval["session_id"],
        event_type=EventType.HUMAN_DECISION,
        data={
            "approval_id": approval_id,
            "decision": decision.upper(),
            "authorized_by": reviewer,
            "reason": f"Human {decision}d write operation {approval['tool_name']}"
        },
        step=1
    )

    if decision == "reject":
        approval["status"] = "rejected"
        print(f"[HITL Gate] REJECTED — {approval_id} by {reviewer}")
        return RedirectResponse(url="/pending-approvals", status_code=303)

    # APPROVED — execute the mock write operation now, never before
    if approval["tool_name"] == "apply_firmware_update":
        result = mock_apply_firmware_update(
            device_id=approval["params"].get("device_id"),
            target_version=approval["params"].get("target_version")
        )
    else:
        result = {"error": "unknown write tool"}

    approval["result"] = result
    approval["status"] = "executed"

    store.log_event(
        session_id=approval["session_id"],
        event_type=EventType.ACTION_EXECUTED,
        data={
            "action": approval["tool_name"],
            "params": approval["params"],
            "authorized_by": reviewer,
            "result": result
        },
        step=2
    )

    print(f"[HITL Gate] APPROVED — {approval_id} by {reviewer} — executed")
    return RedirectResponse(url="/pending-approvals", status_code=303)


@app.get("/tools")
async def list_tools():
    return {
        "tools": [
            {
                "name": "check_device_compliance",
                "description": "Read-only device compliance check. Executes immediately.",
                "parameters": {"device_id": {"type": "string"}}
            },
            {
                "name": "apply_firmware_update",
                "description": "WRITE — schedules a firmware update. Requires human approval.",
                "parameters": {
                    "device_id": {"type": "string"},
                    "target_version": {"type": "string"}
                }
            }
        ]
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "pattern": "MCP02-hitl-gate"}


if __name__ == "__main__":
    print("\n" + "="*60)
    print("MCP02 — HITL Authorization Gate Pattern")
    print("OWASP MCP Risk: MCP02:2025 - Excessive Permissions & Scope Creep")
    print("="*60)
    print("Write operations pause for human approval before executing.")
    print("Review pending approvals at http://localhost:8002/pending-approvals")
    print("="*60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8002)
