"""
MCP09 — Tool Registry Test
-------------------------------
Run this to test the tool registry allowlist pattern end to end.
Make sure server.py is running first in another terminal.

Usage:
    python test_mcp09.py
"""

import asyncio

import httpx

MCP_SERVER_URL = "http://localhost:8009"


async def call(client: httpx.AsyncClient, agent_id: str, tool_name: str, params: dict = None) -> httpx.Response:
    return await client.post(
        f"{MCP_SERVER_URL}/tools/call",
        json={"tool_name": tool_name, "params": params or {}},
        headers={"X-Agent-Id": agent_id} if agent_id is not None else {},
    )


async def test_allowed_tool_call_succeeds(client: httpx.AsyncClient) -> bool:
    print("Test 1: Allowed tool call succeeds")
    response = await call(client, "compliance-agent-001", "check_compliance", {"device_id": "D-1042"})

    ok = response.status_code == 200
    print(f"  {'✅' if ok else '❌'} Status: {response.status_code}\n")
    return ok


async def test_unauthorized_tool_blocked(client: httpx.AsyncClient) -> bool:
    print("Test 2: Unauthorized tool blocked (tool exists, not on role's allowlist) -> 403")
    response = await call(client, "compliance-agent-001", "export_all_device_data")

    ok = response.status_code == 403
    print(f"  {'✅' if ok else '❌'} Status: {response.status_code}\n")
    return ok


async def test_unknown_tool_blocked(client: httpx.AsyncClient) -> bool:
    print("Test 3: Unknown tool blocked -> 404")
    response = await call(client, "compliance-agent-001", "delete_everything")

    ok = response.status_code == 404
    print(f"  {'✅' if ok else '❌'} Status: {response.status_code}\n")
    return ok


async def test_different_role_different_allowlist(client: httpx.AsyncClient) -> bool:
    print("Test 4: Agent with a different role gets a different allowlist")
    compliance = await client.get(f"{MCP_SERVER_URL}/agents/compliance-agent-001/allowed-tools")
    admin = await client.get(f"{MCP_SERVER_URL}/agents/fleet-admin-agent-001/allowed-tools")

    compliance_tools = set(compliance.json()["allowed_tools"])
    admin_tools = set(admin.json()["allowed_tools"])

    ok = compliance_tools != admin_tools and "export_all_device_data" in admin_tools \
        and "export_all_device_data" not in compliance_tools
    print(f"  {'✅' if ok else '❌'} compliance={sorted(compliance_tools)} admin={sorted(admin_tools)}\n")
    return ok


async def test_empty_tool_name_rejected(client: httpx.AsyncClient) -> bool:
    print("Test 5: Empty tool name rejected -> 400")
    response = await call(client, "compliance-agent-001", "")

    ok = response.status_code == 400
    print(f"  {'✅' if ok else '❌'} Status: {response.status_code}\n")
    return ok


async def test_registry_returns_allowed_tools(client: httpx.AsyncClient) -> bool:
    print("Test 6: Registry returns the list of allowed tools for an agent")
    response = await client.get(f"{MCP_SERVER_URL}/agents/compliance-agent-001/allowed-tools")
    body = response.json()

    ok = response.status_code == 200 and set(body["allowed_tools"]) == {"check_compliance", "get_device_status"}
    print(f"  {'✅' if ok else '❌'} Status: {response.status_code}, allowed_tools: {body.get('allowed_tools')}\n")
    return ok


async def main():
    print("\n" + "=" * 60)
    print("MCP09 — Tool Registry Allowlist Test")
    print("=" * 60)
    print("Verifying tool calls are gated by an explicit per-role allowlist\n")

    results = []
    async with httpx.AsyncClient() as client:
        results.append(await test_allowed_tool_call_succeeds(client))
        results.append(await test_unauthorized_tool_blocked(client))
        results.append(await test_unknown_tool_blocked(client))
        results.append(await test_different_role_different_allowlist(client))
        results.append(await test_empty_tool_name_rejected(client))
        results.append(await test_registry_returns_allowed_tools(client))

    passed = sum(results)
    print("=" * 60)
    print(f"Results: {passed}/{len(results)} passed")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
