"""
MCP08 — Session Recording Pattern
-----------------------------------
MCP server that records every tool call and response for full audit trail.
Every decision the agent makes is captured — rewindable to any point.

OWASP MCP Risk: MCP08:2025 - Audit & Logging Deficiencies
"""

import json
import uuid
from datetime import datetime
from typing import Any, Dict
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

from session_store import SessionStore, EventType

app = FastAPI(title="Secure MCP Server — MCP08 Session Recording")
store = SessionStore()


class ToolRequest(BaseModel):
    tool_name: str
    params: Dict[str, Any]
    session_id: str
    step: int
    agent_reasoning: str = ""  # What the agent was thinking before calling this tool


class ToolResponse(BaseModel):
    result: Dict[str, Any]
    tool_name: str
    session_id: str
    step: int
    timestamp: str


@app.post("/session/start")
async def start_session(data: Dict[str, Any]):
    """Record session start."""
    session_id = data.get("session_id", str(uuid.uuid4()))
    store.log_event(
        session_id=session_id,
        event_type=EventType.SESSION_START,
        data={"goal": data.get("goal", ""), "context": data.get("context", {})},
        step=0
    )
    return {"session_id": session_id}


@app.post("/session/end")
async def end_session(data: Dict[str, Any]):
    """Record session end."""
    store.log_event(
        session_id=data["session_id"],
        event_type=EventType.SESSION_END,
        data={"outcome": data.get("outcome", ""), "summary": data.get("summary", "")},
        step=data.get("step", 999)
    )
    return {"status": "session_ended"}


@app.post("/tools/call")
async def call_tool(request: ToolRequest) -> ToolResponse:
    """
    Execute tool and record the full interaction.
    Both the call AND the response are logged — not just that a call happened.
    """

    # Record agent reasoning that led to this call
    if request.agent_reasoning:
        store.log_event(
            session_id=request.session_id,
            event_type=EventType.AGENT_REASONING,
            data={"reasoning": request.agent_reasoning},
            step=request.step
        )

    # Record the tool call
    store.log_event(
        session_id=request.session_id,
        event_type=EventType.TOOL_CALL,
        data={
            "tool_name": request.tool_name,
            "params": request.params
        },
        step=request.step + 1
    )

    # Execute the tool
    result = await execute_tool(request.tool_name, request.params)

    # Record the tool response
    store.log_event(
        session_id=request.session_id,
        event_type=EventType.TOOL_RESPONSE,
        data={
            "tool_name": request.tool_name,
            "result": result
        },
        step=request.step + 2
    )

    return ToolResponse(
        result=result,
        tool_name=request.tool_name,
        session_id=request.session_id,
        step=request.step + 2,
        timestamp=datetime.utcnow().isoformat()
    )


@app.post("/action/execute")
async def execute_action(data: Dict[str, Any]):
    """Record and execute a final action."""

    # Record the action
    store.log_event(
        session_id=data["session_id"],
        event_type=EventType.ACTION_EXECUTED,
        data={
            "action": data.get("action"),
            "params": data.get("params", {}),
            "authorized_by": data.get("authorized_by", "system")
        },
        step=data.get("step", 10)
    )

    return {
        "status": "executed",
        "action_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/sessions/{session_id}")
async def get_session(session_id: str):
    """Retrieve full session log for replay."""
    try:
        events = store.get_session(session_id)
        return {"session_id": session_id, "events": events}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/sessions")
async def list_sessions():
    """List all recorded sessions."""
    return {"sessions": store.list_sessions()}


async def execute_tool(tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Mock tool execution."""
    if tool_name == "check_device_compliance":
        device_id = params.get("device_id")
        mock_data = {
            "D-1042": {"compliance": "NON_COMPLIANT", "firmware": "2.3.1", "required": "2.4.0"},
            "D-1043": {"compliance": "COMPLIANT", "firmware": "2.4.1", "required": "2.4.0"},
        }
        data = mock_data.get(device_id, {"error": "device not found"})
        return {"device_id": device_id, **data}

    raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' not found")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("MCP08 — Session Recording & Replay Pattern")
    print("OWASP MCP Risk: MCP08:2025 - Audit & Logging Deficiencies")
    print("="*60)
    print("Every tool call, response, and decision is recorded.")
    print("Sessions are replayable for forensic investigation.")
    print("="*60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8008)
