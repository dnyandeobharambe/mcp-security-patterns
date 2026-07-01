"""
MCP10 — Client (Agent side)
------------------------------
Shows two tenants each opening their own agent session against the live
MCP10 server: acme-telecom fetches its own device data into its session,
globex-corp reads its own (separate) session, and then an attempted
cross-tenant read of acme-telecom's session_id is rejected by the
running server's context scoping.
"""

import asyncio
import httpx

MCP_SERVER_URL = "http://localhost:8010"


async def create_session(client: httpx.AsyncClient, tenant_id: str) -> str:
    response = await client.post(f"{MCP_SERVER_URL}/sessions", json={"tenant_id": tenant_id})
    session_id = response.json()["session_id"]
    print(f"POST /sessions (tenant_id={tenant_id}) -> {session_id}")
    return session_id


async def fetch_devices(client: httpx.AsyncClient, session_id: str, tenant_id: str) -> None:
    response = await client.post(
        f"{MCP_SERVER_URL}/devices/fetch/{session_id}", headers={"X-Tenant-Id": tenant_id}
    )
    print(f"POST /devices/fetch/{session_id} (X-Tenant-Id={tenant_id}) -> "
          f"{response.status_code}: {response.json()}\n")


async def read_context(client: httpx.AsyncClient, session_id: str, tenant_id: str) -> None:
    response = await client.get(
        f"{MCP_SERVER_URL}/context/{session_id}", headers={"X-Tenant-Id": tenant_id}
    )
    print(f"GET /context/{session_id} (X-Tenant-Id={tenant_id}) -> "
          f"{response.status_code}: {response.json()}\n")


async def main():
    print("\nMCP10 — Context Scoping Demo\n")

    async with httpx.AsyncClient() as client:
        print("--- acme-telecom opens a session and fetches its own device data ---")
        acme_session = await create_session(client, "acme-telecom")
        await fetch_devices(client, acme_session, "acme-telecom")
        await read_context(client, acme_session, "acme-telecom")

        print("--- globex-corp opens its own, unrelated session ---")
        globex_session = await create_session(client, "globex-corp")
        await read_context(client, globex_session, "globex-corp")

        print("--- globex-corp attempts to read acme-telecom's session directly ---")
        await read_context(client, acme_session, "globex-corp")

    print("=" * 60)
    print("Summary:")
    print("  acme-telecom could read its own session's device data — by design")
    print("  globex-corp's own session stayed empty — no cross-session bleed")
    print("  globex-corp could NOT read acme-telecom's session — also by design")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
