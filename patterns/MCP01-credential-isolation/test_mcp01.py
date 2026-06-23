"""
MCP01 — Credential Isolation Test
------------------------------------
Run this to test credential isolation pattern.
Make sure server.py is running first in another terminal.

Usage:
    python test_mcp01.py
"""

import httpx
import asyncio
import json


MCP_SERVER_URL = "http://localhost:8001"

TEST_DEVICES = [
    ("D-1042", "NON_COMPLIANT"),
    ("D-1043", "COMPLIANT"),
]


async def test_device(client: httpx.AsyncClient, device_id: str, expected: str):
    """Test device compliance check — verify no credentials in response."""
    response = await client.post(
        f"{MCP_SERVER_URL}/tools/call",
        json={
            "tool_name": "check_device_compliance",
            "params": {"device_id": device_id},
            "session_id": "test-session-001"
        }
    )
    response.raise_for_status()
    result = response.json()

    # Check compliance result
    compliance = result["result"]["compliance_status"]
    correct = compliance == expected

    # Verify no credentials in response
    result_str = json.dumps(result)
    has_credential = any(keyword in result_str.lower() for keyword in [
        "api_key", "password", "secret", "token", "sk-", "bearer"
    ])

    print(f"Testing {device_id}:")
    print(f"  {'✅' if correct else '❌'} Compliance: {compliance} (expected {expected})")
    print(f"  {'✅' if not has_credential else '❌'} Credentials in response: {'NONE' if not has_credential else 'FOUND — SECURITY ISSUE'}")
    print()

    return correct and not has_credential


async def main():
    print("\n" + "="*60)
    print("MCP01 — Credential Isolation Test")
    print("="*60)
    print("Verifying credentials never appear in agent responses\n")

    passed = 0

    async with httpx.AsyncClient() as client:
        for device_id, expected in TEST_DEVICES:
            success = await test_device(client, device_id, expected)
            if success:
                passed += 1

    print("="*60)
    print(f"Results: {passed}/{len(TEST_DEVICES)} passed")
    print("Credentials exposed to agent: NONE" if passed == len(TEST_DEVICES) else "⚠️ Issues found")
    print("="*60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
