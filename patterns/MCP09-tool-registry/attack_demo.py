"""
MCP09 — Attack Demo
-----------------------
Part 1: No-registry world. The MCP server executes whatever tool name it's
given — there's no concept of "this agent's role doesn't include this
tool." A compliance agent that only needed read-only compliance checks
can call a shadow bulk-export tool and exfiltrate the entire fleet.

Part 2: Tool-registry world. The same compliance agent identity hits the
same shadow tool — and the deny-by-default allowlist rejects it before
the handler ever runs.

⚠️  Part 1 demonstrates the VULNERABLE pattern — do NOT use in production.
"""

from tool_registry import ToolRegistry, TOOL_CATALOG


# ─────────────────────────────────────────────
# Part 1 — No registry (vulnerable)
# ─────────────────────────────────────────────

def legacy_call_tool(tool_name: str, params: dict) -> dict:
    """No allowlist check at all — any known function name executes for any caller."""
    handlers = {
        "check_compliance": lambda p: {"device_id": p.get("device_id"), "compliance": "NON_COMPLIANT"},
        "export_all_device_data": lambda p: {
            "devices": [
                {"device_id": "D-1042", "owner": "acme-telecom", "compliance": "NON_COMPLIANT"},
                {"device_id": "D-1043", "owner": "acme-telecom", "compliance": "COMPLIANT"},
                {"device_id": "D-2091", "owner": "acme-telecom", "compliance": "NON_COMPLIANT"},
            ],
            "exported_count": 3,
        },
    }
    return handlers[tool_name](params)


def run_no_registry_attack():
    print("\n" + "⚠️ " * 20)
    print("VULNERABLE PATTERN — NO TOOL REGISTRY — DO NOT USE IN PRODUCTION")
    print("⚠️ " * 20 + "\n")

    print("compliance-agent-001 was provisioned to do ONE thing: read-only compliance checks.")
    legit = legacy_call_tool("check_compliance", {"device_id": "D-1042"})
    print(f"  check_compliance(D-1042) -> {legit}\n")

    print("Nothing stops the same agent identity from calling a shadow tool it")
    print("was never meant to reach — the server has no concept of 'allowed for this role.'")
    stolen = legacy_call_tool("export_all_device_data", {})
    print(f"  export_all_device_data() -> {stolen}")
    print(f"  Entire fleet exfiltrated by a read-only compliance agent: {stolen['exported_count']} devices\n")


# ─────────────────────────────────────────────
# Part 2 — Tool registry (defense)
# ─────────────────────────────────────────────

def run_registry_defense():
    print("\n" + "✅ " * 20)
    print("WITH Tool Registry — MCP09 Pattern")
    print("✅ " * 20 + "\n")

    registry = ToolRegistry()

    print("compliance-agent-001's role allowlist:")
    print(f"  {registry.get_allowed_tools('compliance-agent-001')}\n")

    print("Allowed call: check_compliance")
    allowed = registry.is_allowed("compliance-agent-001", "check_compliance")
    print(f"  is_allowed(compliance-agent-001, check_compliance) -> {allowed}\n")

    print("Same agent identity attempts the shadow tool that exfiltrated the fleet in Part 1:")
    blocked = registry.is_allowed("compliance-agent-001", "export_all_device_data")
    print(f"  is_allowed(compliance-agent-001, export_all_device_data) -> {blocked}")
    print(f"  Blocked by: deny-by-default role allowlist — tool exists, but not for this role\n")

    print("Same shadow tool reachable by the role it WAS provisioned for:")
    admin_allowed = registry.is_allowed("fleet-admin-agent-001", "export_all_device_data")
    print(f"  is_allowed(fleet-admin-agent-001, export_all_device_data) -> {admin_allowed}")
    print(f"  Explicit allowlist entry, not a blanket trust of 'known tool name'\n")

    print("An entirely unregistered tool name, attempted by any agent:")
    unknown = registry.is_known_tool("delete_everything")
    print(f"  is_known_tool(delete_everything) -> {unknown}")
    print(f"  Rejected before role checks even run — not in the catalog at all\n")


def show_comparison():
    print("\n" + "=" * 60)
    print("ATTACK SURFACE COMPARISON")
    print("=" * 60)

    print("\n❌ No tool registry:")
    print("  - Agent can call any tool whose name it knows: YES")
    print("  - Shadow/deprecated tools reachable by any caller: YES")
    print("  - Role distinctions enforced anywhere: NO")
    print("  - Blast radius of one compromised agent identity: entire tool surface")

    print("\n✅ Tool registry allowlist (MCP09):")
    print(f"  - Tools in catalog: {len(TOOL_CATALOG)}")
    print("  - Unknown tool names: rejected (404), before role checks run")
    print("  - Known tool, wrong role: rejected (403), explicit allowlist miss")
    print("  - Blast radius of one compromised agent identity: only that role's allowlist")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    run_no_registry_attack()
    run_registry_defense()
    show_comparison()
