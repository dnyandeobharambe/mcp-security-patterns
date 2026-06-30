"""
MCP07 — Attack Demo
-----------------------
Part 1: Bearer-token world. A stolen token IS the identity — anyone who
has it can replay it forever, indistinguishably from the real agent.

Part 2: AAuth world. The attacker captures an entire valid signed request
off the wire and still can't do anything useful with it — replay is
blocked by a nonce, and any change to the request invalidates the
signature because the attacker never had the private key.

⚠️  Part 1 demonstrates the VULNERABLE pattern — do NOT use in production.
"""

import json

from aauth import AgentIdentity, AauthRegistry, NonceCache, sign_request, verify_request


# ─────────────────────────────────────────────
# Part 1 — Legacy bearer-token world (vulnerable)
# ─────────────────────────────────────────────

LEGACY_VALID_TOKENS = {"sk-agent-prod-7f3a9c2e1b8d"}


def legacy_authenticate(token: str) -> bool:
    return token in LEGACY_VALID_TOKENS


def legacy_call_tool(token: str, device_id: str) -> dict:
    if not legacy_authenticate(token):
        return {"error": "unauthorized"}
    return {"device_id": device_id, "compliance": "NON_COMPLIANT", "firmware": "2.3.1"}


def run_bearer_token_attack():
    print("\n" + "⚠️ "*20)
    print("VULNERABLE PATTERN — BEARER TOKEN — DO NOT USE IN PRODUCTION")
    print("⚠️ "*20 + "\n")

    token = "sk-agent-prod-7f3a9c2e1b8d"

    print("Legitimate agent calls the legacy MCP server:")
    print(f"  Authorization: Bearer {token}")
    legit_result = legacy_call_tool(token, "D-1042")
    print(f"  -> {legit_result}\n")

    print("That exact header line gets written to a request log / APM trace / proxy.")
    print("An attacker with read access to that log captures the full token.\n")

    print("Attacker replays the EXACT same token from a different machine:")
    print(f"  Authorization: Bearer {token}")
    attacker_result = legacy_call_tool(token, "D-1099")
    print(f"  -> {attacker_result}")
    impersonated = attacker_result.get("error") != "unauthorized"
    print(f"  Server treats attacker as the legitimate agent: {impersonated}\n")


# ─────────────────────────────────────────────
# Part 2 — AAuth world (defense)
# ─────────────────────────────────────────────

def run_aauth_defense():
    print("\n" + "✅ "*20)
    print("WITH AAuth — MCP07 Pattern")
    print("✅ "*20 + "\n")

    registry = AauthRegistry()
    nonces = NonceCache()

    legit = AgentIdentity.generate("agent-fleet-ops")
    registry.register(legit.agent_id, legit.public_key_bytes)
    print(f"Legitimate agent identity registered: {legit.agent_id}")
    print(f"Public key on file: {legit.public_key_hex[:16]}... (private key never leaves the agent)\n")

    body = json.dumps({"tool_name": "check_device_compliance", "params": {"device_id": "D-1042"}}).encode()
    headers = sign_request(legit, "POST", "/tools/call", body)

    print("Legitimate agent sends a signed request:")
    print(f"  {json.dumps(headers, indent=2)}")
    ok, agent_id, reason = verify_request(registry, nonces, "POST", "/tools/call", headers, body)
    print(f"  -> verified={ok}, agent={agent_id}\n")

    print("Attacker captures the ENTIRE request off the wire — headers AND body.")
    print("There is no static secret in it, only a one-time-use proof of possession.\n")

    print("Attack 2a: Attacker replays the captured request verbatim.")
    ok2, _, reason2 = verify_request(registry, nonces, "POST", "/tools/call", headers, body)
    print(f"  -> verified={ok2}, reason='{reason2}'")
    print(f"  Blocked by: nonce reuse detection\n")

    print("Attack 2b: Attacker intercepts a second, not-yet-submitted signed request")
    print("in flight and rewrites the body to escalate to a write tool before forwarding it.")
    second_body = json.dumps({"tool_name": "check_device_compliance", "params": {"device_id": "D-1043"}}).encode()
    second_headers = sign_request(legit, "POST", "/tools/call", second_body)  # fresh, unused nonce
    forged_body = json.dumps({
        "tool_name": "apply_firmware_update",
        "params": {"device_id": "D-1042", "target_version": "0.0.1-malicious"}
    }).encode()
    ok3, _, reason3 = verify_request(registry, nonces, "POST", "/tools/call", second_headers, forged_body)
    print(f"  -> verified={ok3}, reason='{reason3}'")
    print(f"  Blocked by: signature covers the body — changing it invalidates the signature")
    print(f"  Attacker has no private key, so they cannot re-sign and try again\n")


def show_comparison():
    print("\n" + "="*60)
    print("ATTACK SURFACE COMPARISON")
    print("="*60)

    print("\n❌ Bearer token (no AAuth):")
    print("  - Stolen token reusable indefinitely: YES")
    print("  - Stolen token reusable from any machine: YES")
    print("  - Attacker can call ANY tool with a stolen token: YES")
    print("  - Detectable as theft vs. legitimate use: NO")

    print("\n✅ AAuth signed requests (MCP07):")
    print("  - Stolen request replayable: NO (nonce reuse detected)")
    print("  - Stolen request repurposable for a new action: NO (signature covers body)")
    print("  - Forging a new request without the private key: IMPOSSIBLE")
    print("  - What an attacker gains from a full request capture: one already-used, now-dead proof")
    print("="*60 + "\n")


if __name__ == "__main__":
    run_bearer_token_attack()
    run_aauth_defense()
    show_comparison()
