"""
MCP10 — Context Scoping Test
---------------------------------
Run this to test the context scoping pattern end to end.
Make sure server.py is running first in another terminal.

Usage:
    python test_mcp10.py
"""

import asyncio

import httpx

MCP_SERVER_URL = "http://localhost:8010"


async def create_session(client: httpx.AsyncClient, tenant_id: str, ttl_seconds: int = None) -> str:
    body = {"tenant_id": tenant_id}
    if ttl_seconds is not None:
        body["ttl_seconds"] = ttl_seconds
    response = await client.post(f"{MCP_SERVER_URL}/sessions", json=body)
    return response.json()["session_id"]


async def write_context(client: httpx.AsyncClient, session_id: str, tenant_id: str, data: dict) -> httpx.Response:
    return await client.post(
        f"{MCP_SERVER_URL}/context/{session_id}/write",
        json={"data": data},
        headers={"X-Tenant-Id": tenant_id} if tenant_id is not None else {},
    )


async def read_context(client: httpx.AsyncClient, session_id: str, tenant_id: str) -> httpx.Response:
    return await client.get(
        f"{MCP_SERVER_URL}/context/{session_id}",
        headers={"X-Tenant-Id": tenant_id} if tenant_id is not None else {},
    )


async def test_session_reads_own_context(client: httpx.AsyncClient) -> bool:
    print("Test 1: Session reads its own context successfully")
    session_id = await create_session(client, "acme-telecom")
    await write_context(client, session_id, "acme-telecom", {"devices": ["D-1042"]})
    response = await read_context(client, session_id, "acme-telecom")

    ok = response.status_code == 200 and response.json()["context"] == {"devices": ["D-1042"]}
    print(f"  {'✅' if ok else '❌'} Status: {response.status_code}, context: {response.json().get('context')}\n")
    return ok


async def test_different_session_cannot_read_another(client: httpx.AsyncClient) -> bool:
    print("Test 2: Different session cannot read another session's context")
    session_a = await create_session(client, "acme-telecom")
    session_b = await create_session(client, "acme-telecom")
    await write_context(client, session_a, "acme-telecom", {"secret": "session-a-only"})

    response = await read_context(client, session_b, "acme-telecom")

    ok = response.status_code == 200 and response.json()["context"] == {}
    print(f"  {'✅' if ok else '❌'} session_b context: {response.json().get('context')} "
          f"(should not contain session_a's data)\n")
    return ok


async def test_cross_tenant_access_blocked(client: httpx.AsyncClient) -> bool:
    print("Test 3: Cross-tenant access blocked -> 403")
    session_id = await create_session(client, "acme-telecom")
    await write_context(client, session_id, "acme-telecom", {"devices": ["D-1042"]})

    response = await read_context(client, session_id, "globex-corp")

    ok = response.status_code == 403
    print(f"  {'✅' if ok else '❌'} Status: {response.status_code}\n")
    return ok


async def test_expired_context_returns_404(client: httpx.AsyncClient) -> bool:
    print("Test 4: Expired context returns 404")
    session_id = await create_session(client, "acme-telecom", ttl_seconds=-1)

    response = await read_context(client, session_id, "acme-telecom")

    ok = response.status_code == 404
    print(f"  {'✅' if ok else '❌'} Status: {response.status_code}\n")
    return ok


async def test_write_succeeds_for_correct_tenant(client: httpx.AsyncClient) -> bool:
    print("Test 5: Writing to context succeeds for correct tenant")
    session_id = await create_session(client, "globex-corp")

    response = await write_context(client, session_id, "globex-corp", {"devices": ["G-9001"]})
    confirm = await read_context(client, session_id, "globex-corp")

    ok = response.status_code == 200 and confirm.json()["context"] == {"devices": ["G-9001"]}
    print(f"  {'✅' if ok else '❌'} Write status: {response.status_code}, "
          f"confirmed context: {confirm.json().get('context')}\n")
    return ok


async def test_reset_clears_data(client: httpx.AsyncClient) -> bool:
    print("Test 6: Context reset clears data correctly")
    session_id = await create_session(client, "acme-telecom")
    await write_context(client, session_id, "acme-telecom", {"devices": ["D-1042"]})

    reset_response = await client.delete(f"{MCP_SERVER_URL}/reset")
    after_reset = await read_context(client, session_id, "acme-telecom")

    ok = reset_response.status_code == 200 and reset_response.json()["cleared"] >= 1 \
        and after_reset.status_code == 404
    print(f"  {'✅' if ok else '❌'} Reset cleared: {reset_response.json().get('cleared')}, "
          f"post-reset read status: {after_reset.status_code}\n")
    return ok


async def main():
    print("\n" + "=" * 60)
    print("MCP10 — Context Scoping Test")
    print("=" * 60)
    print("Verifying session context is isolated by session_id + tenant_id\n")

    results = []
    async with httpx.AsyncClient() as client:
        results.append(await test_session_reads_own_context(client))
        results.append(await test_different_session_cannot_read_another(client))
        results.append(await test_cross_tenant_access_blocked(client))
        results.append(await test_expired_context_returns_404(client))
        results.append(await test_write_succeeds_for_correct_tenant(client))
        results.append(await test_reset_clears_data(client))

    passed = sum(results)
    print("=" * 60)
    print(f"Results: {passed}/{len(results)} passed")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
