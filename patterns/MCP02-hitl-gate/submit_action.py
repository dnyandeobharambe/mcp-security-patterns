"""
submit_action.py — Submit a write operation to the MCP02 HITL gate server.

Usage:
    python submit_action.py
    python submit_action.py --device D-1043 --version 9.9.9 --reason "Suspicious target version"

What it does:
    1. Builds an apply_firmware_update tool request with a fresh session ID
    2. POSTs it to the running MCP02 server (must already be up on :8002)
    3. The server queues the write and returns immediately — nothing executes yet
    4. Prints the approval_id and the URL to review and decide it

Example output:
    Submitting apply_firmware_update(device=D-1043, version=9.9.9)
    Reason: Suspicious target version

    Approval ID: 3172b5ab-c4b0-4332-addd-8c2a457d2106
    Review at:   http://localhost:8002/pending-approvals
"""

import argparse
import uuid
import httpx


MCP_SERVER_URL = "http://localhost:8002"


def submit_action(device: str, version: str, reason: str) -> dict:
    session_id = str(uuid.uuid4())
    response = httpx.post(f"{MCP_SERVER_URL}/tools/call", json={
        "tool_name": "apply_firmware_update",
        "params": {"device_id": device, "target_version": version},
        "session_id": session_id,
        "agent_reasoning": reason
    }, timeout=30.0)
    response.raise_for_status()
    return response.json()


def main():
    parser = argparse.ArgumentParser(description="Submit a write operation to the MCP02 HITL gate")
    parser.add_argument("--device", default="D-1042", help="Device ID (default: D-1042)")
    parser.add_argument("--version", default="2.4.0", help="Target firmware version (default: 2.4.0)")
    parser.add_argument("--reason", default="Device is non-compliant", help="Agent reasoning for the request")
    args = parser.parse_args()

    print(f"\nSubmitting apply_firmware_update(device={args.device}, version={args.version})")
    print(f"Reason: {args.reason}\n")

    result = submit_action(args.device, args.version, args.reason)

    if result.get("status") != "pending_approval":
        print(f"Unexpected response: {result}")
        return

    print(f"Approval ID: {result['approval_id']}")
    print(f"Review at:   {MCP_SERVER_URL}/pending-approvals\n")


if __name__ == "__main__":
    main()
