"""
MCP09 — Client (Agent side)
------------------------------
Shows compliance-agent-001 calling tools its role is allowlisted for,
then attempting the shadow tool that the attack demo exfiltrated data
with — and getting blocked by the running server's registry.
"""

import asyncio
import httpx

MCP_SERVER_URL = "http://localhost:8009"
AGENT_ID = "compliance-agent-001"


async def call_tool(client: httpx.AsyncClient, agent_id: str, tool_name: str, params: dict) -> None:
    print(f"AGENT ({agent_id}): calling {tool_name}({params})")
    response = await client.post(
        f"{MCP_SERVER_URL}/tools/call",
        json={"tool_name": tool_name, "params": params},
        headers={"X-Agent-Id": agent_id},
    )
    print(f"MCP Server -> {response.status_code}: {response.json()}\n")


async def main():
    print("\nMCP09 — Tool Registry Allowlist Demo")
    print(f"Agent identity: {AGENT_ID}\n")

    async with httpx.AsyncClient() as client:
        allowlist = await client.get(f"{MCP_SERVER_URL}/agents/{AGENT_ID}/allowed-tools")
        print(f"GET /agents/{AGENT_ID}/allowed-tools -> {allowlist.json()}\n")

        print("--- Allowed calls ---")
        await call_tool(client, AGENT_ID, "check_compliance", {"device_id": "D-1042"})
        await call_tool(client, AGENT_ID, "get_device_status", {"device_id": "D-1042"})

        print("--- Unauthorized call (tool exists, not on this role's allowlist) ---")
        await call_tool(client, AGENT_ID, "export_all_device_data", {})

        print("--- Unknown tool (not in the catalog at all) ---")
        await call_tool(client, AGENT_ID, "delete_everything", {})

    print("=" * 60)
    print("Summary:")
    print("  compliance-agent-001 could read compliance/status data — by design")
    print("  compliance-agent-001 could NOT reach the shadow export tool — also by design")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
