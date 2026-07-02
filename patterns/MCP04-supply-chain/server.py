"""
MCP04 — Supply Chain Verification Pattern
--------------------------------------------
Before any tool's artifact is loaded and executed, it must clear two
deterministic checks: its hash must match what a manifest entry recorded
at publish time, and that manifest entry itself must carry a signature
that verifies against an approved publisher's public key. A tool that's
unregistered, whose artifact was tampered with, whose publisher isn't
approved, or whose manifest entry is forged is rejected before its
handler ever runs.

OWASP MCP Risk: MCP04:2025 - Supply Chain Vulnerabilities (via MCP)
"""

from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

from supply_chain import SupplyChainVerifier

app = FastAPI(title="Secure MCP Server — MCP04 Supply Chain Verification")

verifier = SupplyChainVerifier()

# Maps a load-time/publish-time rejection code to an HTTP status.
STATUS_FOR_CODE = {
    "unknown_tool": 404,
    "hash_mismatch": 409,
    "unapproved_publisher": 403,
    "invalid_signature": 401,
}


class PublishRequest(BaseModel):
    tool_name: str
    publisher_id: str
    artifact: str
    signature_hex: str


class ToolCallRequest(BaseModel):
    tool_name: str
    artifact: str
    params: Dict[str, Any] = {}


def mock_compliance_checker(device_id: str) -> Dict[str, Any]:
    mock_devices = {
        "D-1042": {"compliance": "NON_COMPLIANT", "firmware": "2.3.1", "required": "2.4.0"},
        "D-1043": {"compliance": "COMPLIANT", "firmware": "2.4.1", "required": "2.4.0"},
    }
    return {"device_id": device_id, **mock_devices.get(device_id, {"error": "device not found"})}


def mock_firmware_validator(device_id: str, target_version: str) -> Dict[str, Any]:
    return {"device_id": device_id, "target_version": target_version, "valid": True}


SAFE_HANDLERS = {
    "compliance_checker": lambda params: mock_compliance_checker(params.get("device_id")),
    "firmware_validator": lambda params: mock_firmware_validator(
        params.get("device_id"), params.get("target_version")
    ),
}


@app.post("/manifest/publish")
async def publish_tool(request: PublishRequest):
    """
    KEY SECURITY PATTERN (gate 1 of 2):
    A new or replacement manifest entry is only accepted if its
    signature verifies against an APPROVED publisher's public key.
    Claiming a trusted publisher_id is not enough — the caller must
    actually hold that publisher's private key.
    """
    ok, code, reason = verifier.publish(
        request.tool_name, request.publisher_id, request.artifact.encode("utf-8"), request.signature_hex
    )

    if not ok:
        print(f"[SupplyChain] PUBLISH BLOCKED — {reason}")
        raise HTTPException(status_code=STATUS_FOR_CODE[code], detail=reason)

    print(f"[SupplyChain] PUBLISHED — '{request.tool_name}' by '{request.publisher_id}'")
    entry = verifier.get_manifest()[request.tool_name]
    return {"status": "published", "tool_name": entry.tool_name, "publisher_id": entry.publisher_id,
            "expected_hash": entry.expected_hash}


@app.post("/tools/call")
async def call_tool(request: ToolCallRequest):
    """
    KEY SECURITY PATTERN (gate 2 of 2):
    Loading a tool to execute it requires the submitted artifact's hash
    to match the manifest's expected_hash. A tool_name that isn't in the
    manifest, or an artifact whose bytes were swapped or tampered with
    after publish, is rejected before SAFE_HANDLERS ever runs.
    """
    artifact = request.artifact.encode("utf-8")
    ok, code, reason = verifier.verify_and_load(request.tool_name, artifact)

    if not ok:
        print(f"[SupplyChain] LOAD BLOCKED — {reason}")
        raise HTTPException(status_code=STATUS_FOR_CODE[code], detail=reason)

    print(f"[SupplyChain] LOAD VERIFIED — executing '{request.tool_name}'")
    result = SAFE_HANDLERS[request.tool_name](request.params)
    return {"status": "executed", "result": result, "verification": "passed"}


@app.get("/manifest")
async def get_manifest():
    """The current manifest — being listed here means a signature was verified at publish time."""
    return {
        "tools": [
            {"tool_name": e.tool_name, "publisher_id": e.publisher_id, "expected_hash": e.expected_hash}
            for e in verifier.get_manifest().values()
        ]
    }


@app.get("/audit-log")
async def get_audit_log():
    return {
        "entries": [
            {
                "operation": r.operation,
                "tool_name": r.tool_name,
                "publisher_id": r.publisher_id,
                "verified": r.verified,
                "code": r.code,
                "reason": r.reason,
                "ts": r.ts,
            }
            for r in verifier.get_log()
        ]
    }


@app.delete("/reset")
async def reset():
    """Clear the audit log and revert the manifest to its baseline — ready for a fresh demo run."""
    cleared = verifier.reset()
    print(f"[SupplyChain] Reset — cleared {cleared} logged entr(ies), manifest reverted to baseline")
    return {"cleared": cleared, "message": "Ready for new demo"}


@app.get("/health")
async def health():
    return {"status": "healthy", "pattern": "MCP04-supply-chain"}


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("MCP04 — Supply Chain Verification Pattern")
    print("OWASP MCP Risk: MCP04:2025 - Supply Chain Vulnerabilities (via MCP)")
    print("=" * 60)
    print("A tool must clear a signed manifest entry AND a hash match before it loads.")
    print("=" * 60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8004)
