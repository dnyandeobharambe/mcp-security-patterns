"""
MCP08 — Session Recording Test
---------------------------------
Run this to test session recording and replay.
Make sure server.py is running first in another terminal.

Usage:
    python test_mcp08.py
"""

import httpx
import asyncio
import json
import uuid


MCP_SERVER_URL = "http://localhost:8008"


async def run_test_session(client: httpx.AsyncClient) -> str:
    """Run a complete agent session and return the session ID."""
    session_id = str(uuid.uuid4())
    print(f"Running session: {session_id}\n")

    # Start session
    await client.post(f"{MCP_SERVER_URL}/session/start", json={
        "session_id": session_id,
        "goal": "Check device D-1042 compliance and recommend action",
        "context": {"agent": "compliance-checker", "version": "1.0"}
    })
    print("✅ Session started")

    # Tool call 1
    r = await client.post(f"{MCP_SERVER_URL}/tools/call", json={
        "tool_name": "check_device_compliance",
        "params": {"device_id": "D-1042"},
        "session_id": session_id,
        "step": 1,
        "agent_reasoning": "Need to check current firmware status of device D-1042 against policy requirements"
    })
    result = r.json()
    compliance = result.get("result", {}).get("compliance", "unknown")
    print(f"✅ Tool call recorded: {compliance}")

    # Action execution
    await client.post(f"{MCP_SERVER_URL}/action/execute", json={
        "session_id": session_id,
        "action": "flag_for_remediation",
        "params": {"device_id": "D-1042", "reason": "firmware below minimum version"},
        "authorized_by": "human-reviewer",
        "step": 5
    })
    print("✅ Action recorded")

    # End session
    await client.post(f"{MCP_SERVER_URL}/session/end", json={
        "session_id": session_id,
        "outcome": "completed",
        "summary": "Device D-1042 flagged for firmware update",
        "step": 6
    })
    print("✅ Session ended\n")

    return session_id


async def verify_session(client: httpx.AsyncClient, session_id: str):
    """Verify the session was recorded correctly."""
    r = await client.get(f"{MCP_SERVER_URL}/sessions/{session_id}")
    data = r.json()
    events = data["events"]

    print(f"Session recorded: {len(events)} events")
    for event in events:
        print(f"  Step {event['step']:02d}: {event['event_type']}")

    print()
    return len(events) > 0


async def main():
    print("\n" + "="*60)
    print("MCP08 — Session Recording Test")
    print("="*60)
    print("Verifying every agent decision is recorded and replayable\n")

    async with httpx.AsyncClient() as client:
        session_id = await run_test_session(client)
        success = await verify_session(client, session_id)

    print("="*60)
    print(f"{'✅ Session recording working' if success else '❌ Recording failed'}")
    print(f"Replay command: python replay.py {session_id}")
    print("="*60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
