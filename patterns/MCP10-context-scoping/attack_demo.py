"""
MCP10 — Attack Demo
-----------------------
Part 1: No-scoping world. Session context is kept in a single shared
store with no tenant partitioning — a session_id is treated as if it
were already proof of ownership. acme-telecom's agent session fetches
its fleet's device data; globex-corp's agent session, opened moments
later, reads "its" context and gets acme-telecom's data back, because
nothing ever checked which tenant the context belonged to.

Part 2: Context-scoping world. The same two sessions exist behind a
ContextStore that requires session_id AND tenant_id to match before any
read succeeds — so the same cross-tenant read is rejected instead of
silently returning the wrong tenant's data.

⚠️  Part 1 demonstrates the VULNERABLE pattern — do NOT use in production.
"""

from context_scope import ContextStore

MOCK_DEVICE_DATA = {
    "acme-telecom": [
        {"device_id": "D-1042", "compliance": "NON_COMPLIANT", "owner": "acme-telecom"},
        {"device_id": "D-1043", "compliance": "COMPLIANT", "owner": "acme-telecom"},
    ],
    "globex-corp": [
        {"device_id": "G-9001", "compliance": "COMPLIANT", "owner": "globex-corp"},
    ],
}


def mock_fetch_devices(tenant_id: str) -> dict:
    return {"tenant_id": tenant_id, "devices": MOCK_DEVICE_DATA.get(tenant_id, [])}


# ─────────────────────────────────────────────
# Part 1 — No context scoping (vulnerable)
# ─────────────────────────────────────────────

def run_no_scoping_attack():
    print("\n" + "⚠️ " * 20)
    print("VULNERABLE PATTERN — NO CONTEXT SCOPING — DO NOT USE IN PRODUCTION")
    print("⚠️ " * 20 + "\n")

    legacy_context = {}  # ONE shared context object, no per-tenant/per-session partition

    print("acme-telecom opens an agent session and fetches its fleet's device data.")
    acme_result = mock_fetch_devices("acme-telecom")
    legacy_context["devices"] = acme_result["devices"]
    print(f"  session=acme-session-1 fetched -> {acme_result}\n")

    print("globex-corp opens a completely unrelated agent session moments later")
    print("and reads what it believes is its own fresh context...")
    globex_view = {"devices": legacy_context["devices"]}
    print(f"  session=globex-session-1 context read -> {globex_view}")
    print("  globex-corp just received acme-telecom's device data — no session_id/")
    print("  tenant_id check ever ran, so the two sessions shared one context\n")


# ─────────────────────────────────────────────
# Part 2 — Context scoping (defense)
# ─────────────────────────────────────────────

def run_scoping_defense():
    print("\n" + "✅ " * 20)
    print("WITH Context Scoping — MCP10 Pattern")
    print("✅ " * 20 + "\n")

    store = ContextStore()

    acme_session = store.create_session("acme-telecom")
    globex_session = store.create_session("globex-corp")

    print(f"acme-telecom's session: {acme_session}")
    print(f"globex-corp's session:  {globex_session}\n")

    print("acme-telecom's agent fetches its device data into ITS OWN session context:")
    acme_devices = mock_fetch_devices("acme-telecom")["devices"]
    store.write_context(acme_session, {"devices": acme_devices})
    print(f"  write_context({acme_session}, ...) stored under tenant 'acme-telecom'\n")

    print("globex-corp's agent, presenting its OWN tenant_id, reads its OWN session:")
    globex_own = store.read_context(globex_session)
    print(f"  read_context({globex_session}) -> {globex_own}")
    print("  Empty — globex-corp never wrote anything to its own session\n")

    print("Attacker with a stolen/guessed acme-telecom session_id, presenting")
    print("globex-corp's tenant_id, tries to read acme-telecom's session directly:")
    owner_tenant = store.get_tenant(acme_session)
    presented_tenant = "globex-corp"
    blocked = presented_tenant != owner_tenant
    print(f"  session '{acme_session}' belongs to tenant '{owner_tenant}'")
    print(f"  request presented tenant '{presented_tenant}' -> blocked: {blocked}")
    print("  Rejected — session_id alone was never sufficient, tenant_id must match too\n")


def show_comparison():
    print("\n" + "=" * 60)
    print("ATTACK SURFACE COMPARISON")
    print("=" * 60)

    print("\n❌ No context scoping:")
    print("  - Sessions share one undifferentiated context store: YES")
    print("  - A session_id alone treated as proof of ownership: YES")
    print("  - Cross-tenant data exposure via context read: YES")
    print("  - Blast radius of one leaked session_id: every tenant's context")

    print("\n✅ Context scoping (MCP10):")
    print("  - Every session keyed by session_id AND its owning tenant_id")
    print("  - Unknown/expired session_id: rejected (404), before tenant check runs")
    print("  - Known session, wrong tenant_id: rejected (403), explicit mismatch")
    print("  - Blast radius of one leaked session_id: that session's own context only")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    run_no_scoping_attack()
    run_scoping_defense()
    show_comparison()
