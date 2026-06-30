"""
MCP07 — AAuth Agent Identity & Request Signing Pattern
----------------------------------------------------------
Every agent has a cryptographic keypair. Every request is signed.
There is no bearer token to steal — possession of the private key
is the only thing that proves identity.

OWASP MCP Risk: MCP07:2025 - Insecure Credential & Identity Management
Reference: AAuth protocol — github.com/christian-posta/aauth-full-demo
"""

import uuid
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import uvicorn

from aauth import AauthRegistry, NonceCache, verify_request

app = FastAPI(title="Secure MCP Server — MCP07 AAuth")

registry = AauthRegistry()
nonces = NonceCache()


class RegisterRequest(BaseModel):
    agent_id: str
    public_key_hex: str


class ToolRequest(BaseModel):
    tool_name: str
    params: Dict[str, Any]


def mock_check_device_compliance(device_id: str) -> Dict[str, Any]:
    mock_devices = {
        "D-1042": {"compliance": "NON_COMPLIANT", "firmware": "2.3.1", "required": "2.4.0"},
        "D-1043": {"compliance": "COMPLIANT", "firmware": "2.4.1", "required": "2.4.0"},
    }
    return {"device_id": device_id, **mock_devices.get(device_id, {"error": "device not found"})}


def mock_apply_firmware_update(device_id: str, target_version: str) -> Dict[str, Any]:
    return {
        "device_id": device_id,
        "job_id": f"job-{uuid.uuid4().hex[:8]}",
        "target_version": target_version,
        "status": "update_scheduled"
    }


@app.post("/agents/register")
async def register_agent(request: RegisterRequest):
    """
    Simplified stand-in for AAuth's JWKS discovery (/.well-known/aauth-agent).
    In production the server fetches the agent's public key from a
    discoverable endpoint; here the agent registers it directly for the demo.
    """
    registry.register(request.agent_id, bytes.fromhex(request.public_key_hex))
    print(f"[AAuth] Registered agent identity: {request.agent_id}")
    return {"status": "registered", "agent_id": request.agent_id}


@app.post("/tools/call")
async def call_tool(request: Request):
    """
    AAuth-gated tool call.

    KEY SECURITY PATTERN:
    No Authorization header is read or honored here. Identity comes
    entirely from a signature over the method, path, agent id, timestamp,
    nonce, and body — verified against a previously registered public key.
    """
    body = await request.body()
    headers = {
        "X-Aauth-Agent-Id": request.headers.get("x-aauth-agent-id"),
        "X-Aauth-Timestamp": request.headers.get("x-aauth-timestamp"),
        "X-Aauth-Nonce": request.headers.get("x-aauth-nonce"),
        "X-Aauth-Signature": request.headers.get("x-aauth-signature"),
    }

    ok, agent_id, reason = verify_request(registry, nonces, "POST", "/tools/call", headers, body)
    if not ok:
        print(f"[AAuth] REJECTED — {reason}")
        raise HTTPException(status_code=401, detail=reason)

    print(f"[AAuth] Verified request from agent: {agent_id}")

    payload = ToolRequest.model_validate_json(body)

    if payload.tool_name == "check_device_compliance":
        result = mock_check_device_compliance(payload.params.get("device_id"))
        return {"status": "executed", "result": result, "authenticated_agent": agent_id}

    if payload.tool_name == "apply_firmware_update":
        result = mock_apply_firmware_update(
            payload.params.get("device_id"),
            payload.params.get("target_version")
        )
        return {"status": "executed", "result": result, "authenticated_agent": agent_id}

    raise HTTPException(status_code=404, detail=f"Tool '{payload.tool_name}' not found")


@app.delete("/reset")
async def reset():
    """Clear registered agent identities and the nonce cache — ready for a fresh demo run."""
    agents_cleared = registry.reset()
    nonces_cleared = nonces.reset()
    total = agents_cleared + nonces_cleared
    print(f"[AAuth] Reset — cleared {agents_cleared} agent(s), {nonces_cleared} nonce(s)")
    return {"cleared": total, "message": "Ready for new demo"}


@app.get("/tools")
async def list_tools():
    return {
        "tools": [
            {
                "name": "check_device_compliance",
                "description": "Read-only device compliance check. Requires a valid AAuth-signed request.",
                "parameters": {"device_id": {"type": "string"}}
            },
            {
                "name": "apply_firmware_update",
                "description": "WRITE — schedules a firmware update. Requires a valid AAuth-signed request.",
                "parameters": {
                    "device_id": {"type": "string"},
                    "target_version": {"type": "string"}
                }
            }
        ]
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "pattern": "MCP07-oauth-auth"}


if __name__ == "__main__":
    print("\n" + "="*60)
    print("MCP07 — AAuth Agent Identity & Request Signing Pattern")
    print("OWASP MCP Risk: MCP07:2025 - Insecure Credential & Identity Management")
    print("="*60)
    print("No bearer tokens. Every request proves possession of a private key.")
    print("Register an agent at POST /agents/register, then sign with aauth.sign_request().")
    print("="*60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8007)
