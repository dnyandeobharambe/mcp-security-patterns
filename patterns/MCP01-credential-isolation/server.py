"""
MCP01 — Credential Isolation Pattern
-------------------------------------
Secure MCP server that retrieves credentials from Key Vault at execution time.
The agent context NEVER contains credentials — only tool results.

OWASP MCP Risk: MCP01:2025 - Token Mismanagement & Secret Exposure
"""

import asyncio
import json
from datetime import datetime
from typing import Any, Dict
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx
import uvicorn

from mock_key_vault import get_key_vault

app = FastAPI(title="Secure MCP Server — MCP01 Credential Isolation")

# Key Vault instance — initialized once, secrets fetched per request
key_vault = get_key_vault()


# ─────────────────────────────────────────────
# Request / Response models
# ─────────────────────────────────────────────

class ToolRequest(BaseModel):
    tool_name: str
    params: Dict[str, Any]
    session_id: str  # For audit logging


class ToolResponse(BaseModel):
    result: Dict[str, Any]
    tool_name: str
    session_id: str
    timestamp: str
    # NOTE: No credentials in response — ever


# ─────────────────────────────────────────────
# Mock enterprise device API
# (Replace with real API in production)
# ─────────────────────────────────────────────

async def call_device_api(device_id: str, api_key: str) -> Dict[str, Any]:
    """
    Calls the enterprise device management API.
    api_key is used here and immediately discarded — never stored or returned.
    """
    # Mock response — replace with real httpx call in production
    # Example production call:
    # async with httpx.AsyncClient() as client:
    #     response = await client.get(
    #         f"https://api.devices.internal/v1/devices/{device_id}",
    #         headers={"Authorization": f"Bearer {api_key}"}
    #     )
    #     return response.json()

    print(f"[DeviceAPI] Calling with API key: {api_key[:8]}... (truncated for logs)")

    mock_devices = {
        "D-1042": {
            "device_id": "D-1042",
            "firmware_version": "2.3.1",
            "required_firmware": "2.4.0",
            "status": "online",
            "compliance": "NON_COMPLIANT",
            "last_seen": "2026-06-18T22:00:00Z"
        },
        "D-1043": {
            "device_id": "D-1043",
            "firmware_version": "2.4.1",
            "required_firmware": "2.4.0",
            "status": "online",
            "compliance": "COMPLIANT",
            "last_seen": "2026-06-18T22:01:00Z"
        }
    }

    if device_id not in mock_devices:
        raise ValueError(f"Device {device_id} not found")

    return mock_devices[device_id]


# ─────────────────────────────────────────────
# MCP Tool endpoints
# ─────────────────────────────────────────────

@app.get("/tools")
async def list_tools():
    """MCP tool discovery — agent learns what tools are available."""
    return {
        "tools": [
            {
                "name": "check_device_compliance",
                "description": "Check device firmware compliance status. Returns compliance verdict and current firmware version.",
                "parameters": {
                    "device_id": {
                        "type": "string",
                        "description": "The device ID to check (e.g. D-1042)"
                    }
                }
                # NOTE: No mention of credentials here
                # The agent has NO IDEA how authentication works server-side
            }
        ]
    }


@app.post("/tools/call")
async def call_tool(request: ToolRequest) -> ToolResponse:
    """
    Execute a tool call from the agent.

    KEY SECURITY PATTERN:
    1. Agent sends tool call with device_id only — no credentials
    2. This endpoint fetches credentials from Key Vault at execution time
    3. Uses credentials to call enterprise API
    4. Returns result only — credentials never leave this function
    """

    print(f"\n[MCP Server] Tool call received: {request.tool_name}")
    print(f"[MCP Server] Session: {request.session_id}")
    print(f"[MCP Server] Params: {request.params}")

    if request.tool_name == "check_device_compliance":
        device_id = request.params.get("device_id")
        if not device_id:
            raise HTTPException(status_code=400, detail="device_id required")

        # ─── CREDENTIAL ISOLATION HAPPENS HERE ───
        # Step 1: Fetch credential from Key Vault at execution time
        print(f"[KeyVault] Fetching credential for device API...")
        api_key = await key_vault.get_secret("device-api-key")
        # api_key exists ONLY in this function scope

        # Step 2: Call enterprise API with credential
        print(f"[DeviceAPI] Calling with fetched credential...")
        device_data = await call_device_api(device_id, api_key)

        # Step 3: Credential goes out of scope here — never stored, never returned
        del api_key  # Explicit deletion for clarity

        # Step 4: Return result only — clean, no credentials
        result = {
            "device_id": device_data["device_id"],
            "compliance_status": device_data["compliance"],
            "firmware_current": device_data["firmware_version"],
            "firmware_required": device_data["required_firmware"],
            "device_status": device_data["status"],
            "checked_at": datetime.utcnow().isoformat()
            # NOTE: No api_key, no auth token, nothing sensitive
        }

        print(f"[MCP Server] Result: {json.dumps(result, indent=2)}")
        print(f"[MCP Server] Credential was used and discarded — not in response")

        return ToolResponse(
            result=result,
            tool_name=request.tool_name,
            session_id=request.session_id,
            timestamp=datetime.utcnow().isoformat()
        )

    raise HTTPException(status_code=404, detail=f"Tool '{request.tool_name}' not found")


@app.get("/health")
async def health():
    return {"status": "healthy", "pattern": "MCP01-credential-isolation"}


if __name__ == "__main__":
    print("\n" + "="*60)
    print("MCP01 — Credential Isolation Pattern")
    print("OWASP MCP Risk: MCP01:2025 - Token Mismanagement")
    print("="*60)
    print("Credentials are NEVER passed to agent context.")
    print("They are fetched from Key Vault at execution time only.")
    print("="*60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8001)
