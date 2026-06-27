"""
MCP02 — HITL Gate Test
---------------------------
Run this to test both the approval and rejection flows.
Make sure server.py is running first in another terminal.

Usage:
    python test_mcp02.py
"""

import httpx
import asyncio
import uuid


MCP_SERVER_URL = "http://localhost:8002"


async def submit_write_request(client: httpx.AsyncClient, device_id: str, target_version: str) -> str:
    """Agent submits a write request — should come back pending, never executed."""
    response = await client.post(f"{MCP_SERVER_URL}/tools/call", json={
        "tool_name": "apply_firmware_update",
        "params": {"device_id": device_id, "target_version": target_version},
        "session_id": str(uuid.uuid4()),
        "step": 1,
        "agent_reasoning": f"Device {device_id} is non-compliant, proposing update to {target_version}"
    })
    response.raise_for_status()
    result = response.json()
    assert result["status"] == "pending_approval", f"Write executed without approval! {result}"
    return result["approval_id"]


async def decide(client: httpx.AsyncClient, approval_id: str, decision: str, reviewer: str = "test-reviewer@company.com") -> httpx.Response:
    """Simulate a human clicking Approve or Reject on the HTML page. Server replies with a redirect, not JSON."""
    response = await client.post(
        f"{MCP_SERVER_URL}/approvals/{approval_id}/decide",
        data={"decision": decision, "reviewer": reviewer},
        follow_redirects=False
    )
    if response.status_code != 303:
        response.raise_for_status()
    return response


async def get_status(client: httpx.AsyncClient, approval_id: str) -> dict:
    response = await client.get(f"{MCP_SERVER_URL}/approvals/{approval_id}")
    response.raise_for_status()
    return response.json()


async def test_approval_flow(client: httpx.AsyncClient) -> bool:
    print("Test 1: Approval flow")
    approval_id = await submit_write_request(client, "D-1042", "2.4.0")
    print(f"  Write queued: approval_id={approval_id}")

    await decide(client, approval_id, "approve")
    status = await get_status(client, approval_id)

    executed = status["status"] == "executed" and status["result"] is not None
    icon = "✅" if executed else "❌"
    print(f"  {icon} Status after approval: {status['status']}")
    print(f"     Result: {status.get('result')}")
    print(f"     Decided by: {status.get('decided_by')}\n")
    return executed


async def test_rejection_flow(client: httpx.AsyncClient) -> bool:
    print("Test 2: Rejection flow")
    approval_id = await submit_write_request(client, "D-1043", "9.9.9")
    print(f"  Write queued: approval_id={approval_id}")

    await decide(client, approval_id, "reject")
    status = await get_status(client, approval_id)

    blocked = status["status"] == "rejected" and status["result"] is None
    icon = "✅" if blocked else "❌"
    print(f"  {icon} Status after rejection: {status['status']}")
    print(f"     Result (should be None — never executed): {status.get('result')}")
    print(f"     Decided by: {status.get('decided_by')}\n")
    return blocked


async def test_double_decision_rejected(client: httpx.AsyncClient) -> bool:
    print("Test 3: Cannot decide an already-decided approval")
    approval_id = await submit_write_request(client, "D-1044", "2.4.0")
    await decide(client, approval_id, "approve")

    response = await client.post(
        f"{MCP_SERVER_URL}/approvals/{approval_id}/decide",
        data={"decision": "reject", "reviewer": "second-reviewer@company.com"}
    )
    rejected_second_decision = response.status_code == 400
    icon = "✅" if rejected_second_decision else "❌"
    print(f"  {icon} Second decision on same approval rejected: {response.status_code}\n")
    return rejected_second_decision


async def main():
    print("\n" + "="*60)
    print("MCP02 — HITL Authorization Gate Test")
    print("="*60)
    print("Verifying write operations never execute without human approval\n")

    results = []
    async with httpx.AsyncClient() as client:
        results.append(await test_approval_flow(client))
        results.append(await test_rejection_flow(client))
        results.append(await test_double_decision_rejected(client))

    passed = sum(results)
    print("="*60)
    print(f"Results: {passed}/{len(results)} passed")
    print("="*60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
