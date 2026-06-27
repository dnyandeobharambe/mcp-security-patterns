"""
MCP05/06 — Probabilistic Triage Gate Pattern
------------------------------------------------
Every agent-bound query is classified before it reaches tool execution.
HARMFUL queries never reach the agent. UNCERTAIN queries are held for
human review. Only SAFE queries pass through.

OWASP MCP Risk: MCP05/06:2025 - Command Injection & Intent Flow Subversion
"""

from datetime import datetime
from typing import Any, Dict
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

from triage_gate import get_triage_gate, Verdict

app = FastAPI(title="Secure MCP Server — MCP05/06 Triage Gate")
gate = get_triage_gate()


class ToolRequest(BaseModel):
    tool_name: str
    params: Dict[str, Any]
    session_id: str


def execute_agent_action(query: str) -> Dict[str, Any]:
    """The action the agent takes once a query has cleared the gate as SAFE."""
    return {
        "action": "executed",
        "query": query,
        "output": f"Processed request: '{query}'"
    }


@app.post("/tools/call")
async def call_tool(request: ToolRequest):
    """
    Route the query through the triage gate BEFORE the agent acts on it.

    HARMFUL  -> blocked immediately, logged
    UNCERTAIN -> held for review, alert printed to console
    SAFE     -> passed through to the agent action
    """

    if request.tool_name != "agent_query":
        return {"error": f"Tool '{request.tool_name}' not found"}

    query = request.params.get("query", "")
    print(f"\n[Server] Incoming query — session {request.session_id}:")
    print(f"  {query!r}")

    verdict, reason = gate.classify(query)
    timestamp = datetime.utcnow().isoformat()

    if verdict == Verdict.HARMFUL:
        print(f"[TriageGate] BLOCKED — {reason}")
        return {
            "verdict": verdict.value,
            "status": "blocked",
            "reason": reason,
            "session_id": request.session_id,
            "timestamp": timestamp
        }

    if verdict == Verdict.UNCERTAIN:
        print("\n" + "!"*60)
        print("[TriageGate] ALERT — UNCERTAIN query held for review")
        print(f"  Session: {request.session_id}")
        print(f"  Query:   {query!r}")
        print(f"  Reason:  {reason}")
        print("!"*60 + "\n")
        return {
            "verdict": verdict.value,
            "status": "held_for_review",
            "reason": reason,
            "session_id": request.session_id,
            "timestamp": timestamp
        }

    # SAFE — pass through to the agent
    print(f"[TriageGate] SAFE — {reason}")
    result = execute_agent_action(query)
    return {
        "verdict": verdict.value,
        "status": "executed",
        "reason": reason,
        "result": result,
        "session_id": request.session_id,
        "timestamp": timestamp
    }


@app.get("/tools")
async def list_tools():
    return {
        "tools": [{
            "name": "agent_query",
            "description": "Submit a natural-language request for the agent to act on. Routed through the triage gate first.",
            "parameters": {"query": {"type": "string"}}
        }]
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "pattern": "MCP05-06-triage-gate"}


if __name__ == "__main__":
    print("\n" + "="*60)
    print("MCP05/06 — Probabilistic Triage Gate Pattern")
    print("OWASP MCP Risk: MCP05/06:2025 - Command Injection & Intent Flow Subversion")
    print("="*60)
    print("Every query is classified HARMFUL / SAFE / UNCERTAIN")
    print("before it reaches the agent.")
    print("="*60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8056)
