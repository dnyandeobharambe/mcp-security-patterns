"""
MCP09 — Tool Registry Allowlist Pattern
----------------------------------------
An agent identity (X-Agent-Id header) may only call tools its role is
explicitly allowlisted for. A tool call is rejected if the tool doesn't
exist (404), or if it exists but isn't on the caller's allowlist (403).
There is no implicit trust — deny by default, allow only what's listed.

OWASP MCP Risk: MCP09:2025 - Rogue/Unverified MCP Servers & Tools
"""

import uuid
from typing import Any, Dict

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import uvicorn

from tool_registry import ToolRegistry, TOOL_CATALOG

app = FastAPI(title="Secure MCP Server — MCP09 Tool Registry")

registry = ToolRegistry()


class ToolRequest(BaseModel):
    tool_name: str
    params: Dict[str, Any] = {}


def mock_check_compliance(device_id: str) -> Dict[str, Any]:
    mock_devices = {
        "D-1042": {"compliance": "NON_COMPLIANT", "firmware": "2.3.1", "required": "2.4.0"},
        "D-1043": {"compliance": "COMPLIANT", "firmware": "2.4.1", "required": "2.4.0"},
    }
    return {"device_id": device_id, **mock_devices.get(device_id, {"error": "device not found"})}


def mock_get_device_status(device_id: str) -> Dict[str, Any]:
    return {"device_id": device_id, "status": "online", "uptime_hours": 482}


def mock_apply_firmware_update(device_id: str, target_version: str) -> Dict[str, Any]:
    return {
        "device_id": device_id,
        "job_id": f"job-{uuid.uuid4().hex[:8]}",
        "target_version": target_version,
        "status": "update_scheduled",
    }


def mock_export_all_device_data() -> Dict[str, Any]:
    """Shadow tool — bulk dump of every device's data in one call."""
    return {
        "devices": [
            {"device_id": "D-1042", "compliance": "NON_COMPLIANT", "owner": "acme-telecom"},
            {"device_id": "D-1043", "compliance": "COMPLIANT", "owner": "acme-telecom"},
        ],
        "exported_count": 2,
    }


def mock_admin_reset_device(device_id: str) -> Dict[str, Any]:
    return {"device_id": device_id, "status": "factory_reset_scheduled"}


TOOL_HANDLERS = {
    "check_compliance": lambda params: mock_check_compliance(params.get("device_id")),
    "get_device_status": lambda params: mock_get_device_status(params.get("device_id")),
    "apply_firmware_update": lambda params: mock_apply_firmware_update(
        params.get("device_id"), params.get("target_version")
    ),
    "export_all_device_data": lambda params: mock_export_all_device_data(),
    "admin_reset_device": lambda params: mock_admin_reset_device(params.get("device_id")),
}


@app.post("/tools/call")
async def call_tool(request: ToolRequest, x_agent_id: str = Header(default=None)):
    """
    KEY SECURITY PATTERN:
    Authorization is a deterministic three-step lookup, not an LLM
    decision — empty tool name rejected, unknown tool rejected, known
    tool not on the caller's role allowlist rejected. Only a tool that
    passes all three executes.
    """
    if not request.tool_name:
        raise HTTPException(status_code=400, detail="tool_name is required")

    if not registry.is_known_tool(request.tool_name):
        registry.log_call(x_agent_id or "", request.tool_name, False, "unknown tool")
        raise HTTPException(status_code=404, detail=f"Tool '{request.tool_name}' not found")

    if not registry.is_allowed(x_agent_id or "", request.tool_name):
        role = registry.get_role(x_agent_id or "")
        reason = f"role '{role}' not authorized for tool '{request.tool_name}'" if role \
            else f"unknown agent identity: {x_agent_id}"
        registry.log_call(x_agent_id or "", request.tool_name, False, reason)
        print(f"[Registry] BLOCKED — {reason}")
        raise HTTPException(status_code=403, detail=reason)

    registry.log_call(x_agent_id, request.tool_name, True, "allowed")
    print(f"[Registry] ALLOWED — agent '{x_agent_id}' -> '{request.tool_name}'")

    result = TOOL_HANDLERS[request.tool_name](request.params)
    return {"status": "executed", "result": result, "agent_id": x_agent_id}


@app.get("/agents/{agent_id}/allowed-tools")
async def allowed_tools(agent_id: str):
    role = registry.get_role(agent_id)
    return {
        "agent_id": agent_id,
        "role": role,
        "allowed_tools": registry.get_allowed_tools(agent_id),
    }


@app.get("/tools")
async def list_tools():
    """The full tool catalog — being listed here does not imply any caller may use it."""
    return {
        "tools": [
            {"name": spec.name, "description": spec.description, "sensitivity": spec.sensitivity}
            for spec in TOOL_CATALOG.values()
        ]
    }


@app.delete("/reset")
async def reset():
    """Clear the call audit log — ready for a fresh demo run. Role allowlists are policy, not demo state, and are not reset."""
    cleared = registry.reset_call_log()
    print(f"[Registry] Reset — cleared {cleared} logged call(s)")
    return {"cleared": cleared, "message": "Ready for new demo"}


@app.get("/health")
async def health():
    return {"status": "healthy", "pattern": "MCP09-tool-registry"}


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("MCP09 — Tool Registry Allowlist Pattern")
    print("OWASP MCP Risk: MCP09:2025 - Rogue/Unverified MCP Servers & Tools")
    print("=" * 60)
    print("Deny by default. A tool call must match an explicit role allowlist entry.")
    print("Send X-Agent-Id header on POST /tools/call.")
    print("=" * 60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8009)
