"""
MCP07 — AAuth Pattern Test
-------------------------------
Run this to test the AAuth signing/verification pattern end to end.
Make sure server.py is running first in another terminal.

Usage:
    python test_mcp07.py
"""

import asyncio
import json
import time

import httpx

from aauth import AgentIdentity, sign_request

MCP_SERVER_URL = "http://localhost:8007"


async def register(client: httpx.AsyncClient, identity: AgentIdentity) -> None:
    response = await client.post(f"{MCP_SERVER_URL}/agents/register", json={
        "agent_id": identity.agent_id,
        "public_key_hex": identity.public_key_hex,
    })
    response.raise_for_status()


async def signed_call(client: httpx.AsyncClient, headers: dict, body: bytes) -> httpx.Response:
    return await client.post(
        f"{MCP_SERVER_URL}/tools/call",
        content=body,
        headers={**headers, "Content-Type": "application/json"}
    )


async def test_valid_signed_request_succeeds(client: httpx.AsyncClient) -> bool:
    print("Test 1: Valid signed request succeeds")
    identity = AgentIdentity.generate("test-agent-valid")
    await register(client, identity)

    body = json.dumps({"tool_name": "check_device_compliance", "params": {"device_id": "D-1042"}}).encode()
    headers = sign_request(identity, "POST", "/tools/call", body)
    response = await signed_call(client, headers, body)

    ok = response.status_code == 200
    print(f"  {'✅' if ok else '❌'} Status: {response.status_code}\n")
    return ok


async def test_unregistered_agent_rejected(client: httpx.AsyncClient) -> bool:
    print("Test 2: Unregistered agent identity is rejected")
    identity = AgentIdentity.generate("test-agent-ghost")  # never registered

    body = json.dumps({"tool_name": "check_device_compliance", "params": {"device_id": "D-1042"}}).encode()
    headers = sign_request(identity, "POST", "/tools/call", body)
    response = await signed_call(client, headers, body)

    rejected = response.status_code == 401
    print(f"  {'✅' if rejected else '❌'} Status: {response.status_code}\n")
    return rejected


async def test_tampered_body_rejected(client: httpx.AsyncClient) -> bool:
    print("Test 3: Tampering with the body after signing invalidates the signature")
    identity = AgentIdentity.generate("test-agent-tamper")
    await register(client, identity)

    body = json.dumps({"tool_name": "check_device_compliance", "params": {"device_id": "D-1042"}}).encode()
    headers = sign_request(identity, "POST", "/tools/call", body)

    tampered_body = json.dumps({
        "tool_name": "apply_firmware_update",
        "params": {"device_id": "D-1042", "target_version": "9.9.9"}
    }).encode()
    response = await signed_call(client, headers, tampered_body)

    rejected = response.status_code == 401
    print(f"  {'✅' if rejected else '❌'} Status: {response.status_code}\n")
    return rejected


async def test_replayed_nonce_rejected(client: httpx.AsyncClient) -> bool:
    print("Test 4: Replaying an already-used signed request is rejected")
    identity = AgentIdentity.generate("test-agent-replay")
    await register(client, identity)

    body = json.dumps({"tool_name": "check_device_compliance", "params": {"device_id": "D-1043"}}).encode()
    headers = sign_request(identity, "POST", "/tools/call", body)

    first = await signed_call(client, headers, body)
    second = await signed_call(client, headers, body)

    ok = first.status_code == 200 and second.status_code == 401
    print(f"  {'✅' if ok else '❌'} First call: {first.status_code}, Replay: {second.status_code}\n")
    return ok


async def test_missing_aauth_headers_rejected(client: httpx.AsyncClient) -> bool:
    print("Test 5: A bare bearer-style call with no AAuth headers is rejected")
    body = json.dumps({"tool_name": "check_device_compliance", "params": {"device_id": "D-1042"}}).encode()
    response = await client.post(
        f"{MCP_SERVER_URL}/tools/call",
        content=body,
        headers={"Content-Type": "application/json", "Authorization": "Bearer some-stolen-token"}
    )

    rejected = response.status_code == 401
    print(f"  {'✅' if rejected else '❌'} Status: {response.status_code}\n")
    return rejected


async def test_stale_timestamp_rejected(client: httpx.AsyncClient) -> bool:
    print("Test 6: A timestamp outside the clock-skew window is rejected")
    identity = AgentIdentity.generate("test-agent-stale")
    await register(client, identity)

    stale_timestamp = str(int(time.time()) - 600)  # 10 minutes ago — well outside the 120s window
    body = json.dumps({"tool_name": "check_device_compliance", "params": {"device_id": "D-1042"}}).encode()
    headers = sign_request(identity, "POST", "/tools/call", body, timestamp=stale_timestamp)
    response = await signed_call(client, headers, body)

    rejected = response.status_code == 401
    print(f"  {'✅' if rejected else '❌'} Status: {response.status_code}\n")
    return rejected


async def main():
    print("\n" + "="*60)
    print("MCP07 — AAuth Agent Identity Test")
    print("="*60)
    print("Verifying requests are authenticated by signature, not bearer token\n")

    results = []
    async with httpx.AsyncClient() as client:
        results.append(await test_valid_signed_request_succeeds(client))
        results.append(await test_unregistered_agent_rejected(client))
        results.append(await test_tampered_body_rejected(client))
        results.append(await test_replayed_nonce_rejected(client))
        results.append(await test_missing_aauth_headers_rejected(client))
        results.append(await test_stale_timestamp_rejected(client))

    passed = sum(results)
    print("="*60)
    print(f"Results: {passed}/{len(results)} passed")
    print("="*60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
