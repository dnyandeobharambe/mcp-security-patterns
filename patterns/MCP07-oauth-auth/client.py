"""
MCP07 — Client (Agent side)
------------------------------
Shows how an agent establishes a cryptographic identity, registers its
public key with the MCP server, and signs every tool call. No bearer
token is ever created or transmitted.
"""

import asyncio
import json
import httpx

from aauth import AgentIdentity, sign_request

MCP_SERVER_URL = "http://localhost:8007"


async def register_identity(client: httpx.AsyncClient, identity: AgentIdentity) -> None:
    print(f"AGENT: Generated Ed25519 identity '{identity.agent_id}'")
    print(f"AGENT: Public key (safe to share): {identity.public_key_hex[:16]}...")
    print(f"AGENT: Private key never leaves this process — not sent anywhere\n")

    response = await client.post(f"{MCP_SERVER_URL}/agents/register", json={
        "agent_id": identity.agent_id,
        "public_key_hex": identity.public_key_hex,
    })
    response.raise_for_status()
    print(f"AGENT → MCP Server: registered public key")
    print(f"MCP Server → AGENT: {response.json()}\n")


async def call_tool(client: httpx.AsyncClient, identity: AgentIdentity, tool_name: str, params: dict) -> dict:
    body = json.dumps({"tool_name": tool_name, "params": params}).encode("utf-8")
    headers = sign_request(identity, "POST", "/tools/call", body)

    print(f"AGENT: Signing {tool_name}({params})")
    print(f"AGENT: Headers sent — {list(headers.keys())}")
    print(f"AGENT: No 'Authorization' header. No bearer token. Just a signature.\n")

    response = await client.post(
        f"{MCP_SERVER_URL}/tools/call",
        content=body,
        headers={**headers, "Content-Type": "application/json"}
    )
    response.raise_for_status()
    result = response.json()
    print(f"MCP Server → AGENT: {json.dumps(result, indent=2)}\n")
    return result


async def main():
    print("\nMCP07 — AAuth Pattern Demo")
    print("Agent identity is a keypair, not a shared secret\n")

    identity = AgentIdentity.generate("agent-fleet-ops")

    async with httpx.AsyncClient() as client:
        await register_identity(client, identity)
        await call_tool(client, identity, "check_device_compliance", {"device_id": "D-1042"})
        await call_tool(client, identity, "apply_firmware_update", {"device_id": "D-1042", "target_version": "2.4.0"})

    print("="*60)
    print("Summary:")
    print("  Credential transmitted over the wire: a signature (one-time, request-bound)")
    print("  Reusable by an attacker who captures the whole request: NO")
    print("="*60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
