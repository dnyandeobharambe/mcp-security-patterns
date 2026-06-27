"""
client.py — Agent + human round trip against the MCP02 HITL gate server.

Usage:
    python client.py

What it does:
    1. Agent proposes a firmware update for D-1042 — server queues it and
       returns pending_approval, nothing executes yet
    2. A simulated human reviewer approves it — server runs the mock write
       and logs the decision
    3. Agent proposes a second, suspicious update for D-1043 (target version
       9.9.9 — not a real release) — server queues it
    4. The same simulated human rejects it — server blocks the write and
       logs the decision
    5. Prints the final state of each approval so you can compare the
       executed path against the rejected one

    The "HUMAN" steps are clearly separated from the "AGENT" steps in the
    output — in a real deployment that decision is a browser click on
    /pending-approvals, never agent code. It's only inlined here so the
    full round trip can be demonstrated without a browser.

Example output:
    AGENT: Proposing firmware update for D-1042
    AGENT: Reasoning — Device is NON_COMPLIANT, firmware below minimum required version
    ...
    HUMAN (ops-team@company.com): Reviewing approval 925b96ee-72f4-4a09-95f9-548bf21bb8fc
    HUMAN: Decision — APPROVE
    ...
    Summary:
      D-1042 update: executed (human approved)
      D-1043 update: rejected (human rejected — never reached the device API)
"""

import asyncio
import uuid
import httpx
import json


MCP_SERVER_URL = "http://localhost:8002"


async def agent_propose_firmware_update(device_id: str, target_version: str, reasoning: str) -> dict:
    """
    Simulates an AI agent proposing a write operation.

    Notice what comes back: a pending approval, never a result.
    The agent has no path to make the write happen on its own.
    """
    session_id = str(uuid.uuid4())

    print(f"\n{'='*60}")
    print(f"AGENT: Proposing firmware update for {device_id}")
    print(f"AGENT: Reasoning — {reasoning}")
    print(f"AGENT: Session ID: {session_id}")
    print(f"{'='*60}")

    tool_request = {
        "tool_name": "apply_firmware_update",
        "params": {"device_id": device_id, "target_version": target_version},
        "session_id": session_id,
        "agent_reasoning": reasoning
    }

    print(f"\nAGENT -> MCP Server: {json.dumps(tool_request, indent=2)}")

    async with httpx.AsyncClient() as client:
        response = await client.post(f"{MCP_SERVER_URL}/tools/call", json=tool_request, timeout=30.0)
        response.raise_for_status()
        result = response.json()

    print(f"\nMCP Server -> AGENT: {json.dumps(result, indent=2)}")
    print("AGENT: Write did NOT execute. Waiting on a human decision at /pending-approvals")

    return result


async def human_reviews_and_decides(approval_id: str, decision: str, reviewer: str) -> dict:
    """
    Simulates a human opening /pending-approvals and clicking Approve or Reject.
    In a real deployment this is a browser click, not agent code — shown here
    only to demonstrate the full round trip without a browser.
    """
    print(f"\n{'-'*60}")
    print(f"HUMAN ({reviewer}): Reviewing approval {approval_id}")
    print(f"HUMAN: Decision — {decision.upper()}")
    print(f"{'-'*60}")

    async with httpx.AsyncClient() as client:
        decide_response = await client.post(
            f"{MCP_SERVER_URL}/approvals/{approval_id}/decide",
            data={"decision": decision, "reviewer": reviewer},
            follow_redirects=False
        )
        if decide_response.status_code not in (200, 303):
            decide_response.raise_for_status()

        status_response = await client.get(f"{MCP_SERVER_URL}/approvals/{approval_id}")
        status_response.raise_for_status()
        return status_response.json()


async def main():
    print("\nMCP02 — HITL Authorization Gate Demo")
    print("Agent proposes write operations. Only a human can make them execute.\n")

    # Case 1 — legitimate update, human approves
    proposal = await agent_propose_firmware_update(
        device_id="D-1042",
        target_version="2.4.0",
        reasoning="Device is NON_COMPLIANT, firmware below minimum required version"
    )
    approved_result = await human_reviews_and_decides(
        approval_id=proposal["approval_id"],
        decision="approve",
        reviewer="ops-team@company.com"
    )
    print(f"\nFINAL STATE: {json.dumps(approved_result, indent=2)}")

    # Case 2 — suspicious update, human rejects
    proposal2 = await agent_propose_firmware_update(
        device_id="D-1043",
        target_version="9.9.9",
        reasoning="Update requested — target version does not match any known release"
    )
    rejected_result = await human_reviews_and_decides(
        approval_id=proposal2["approval_id"],
        decision="reject",
        reviewer="ops-team@company.com"
    )
    print(f"\nFINAL STATE: {json.dumps(rejected_result, indent=2)}")

    print(f"\n{'='*60}")
    print("Summary:")
    print(f"  D-1042 update: {approved_result['status']} (human approved)")
    print(f"  D-1043 update: {rejected_result['status']} (human rejected — never reached the device API)")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    asyncio.run(main())
