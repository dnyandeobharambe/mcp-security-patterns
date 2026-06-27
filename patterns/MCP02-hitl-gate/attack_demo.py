"""
MCP02 — Attack Demo
-----------------------
Shows what happens WITHOUT an HITL gate. The agent has write access
and uses it immediately — no pause, no human review, no approval trail.

⚠️  This demonstrates the VULNERABLE pattern — do NOT use in production.
"""

import uuid

WRITE_REQUESTS = [
    {"device_id": "D-1042", "target_version": "2.4.0"},
    {"device_id": "D-1043", "target_version": "9.9.9"},  # attacker-supplied bogus version
    {"device_id": "D-1044", "target_version": "2.4.0"},
]


def vulnerable_agent_writes_directly(device_id: str, target_version: str) -> dict:
    """
    The wrong way — the agent calls the write tool and it executes immediately.
    No human ever sees the proposed action before it happens.
    """
    return {
        "device_id": device_id,
        "job_id": f"job-{uuid.uuid4().hex[:8]}",
        "target_version": target_version,
        "status": "update_scheduled"
    }


def run_without_gate():
    print("\n" + "⚠️ "*20)
    print("VULNERABLE PATTERN — NO HITL GATE — DO NOT USE IN PRODUCTION")
    print("⚠️ "*20 + "\n")

    for req in WRITE_REQUESTS:
        result = vulnerable_agent_writes_directly(**req)
        print(f"Write request: apply_firmware_update({req})")
        print(f"  -> EXECUTED IMMEDIATELY (no approval, no human in the loop)")
        print(f"     job_id={result['job_id']}\n")


def run_with_gate():
    print("\n" + "✅ "*20)
    print("WITH HITL GATE — MCP02 Pattern")
    print("✅ "*20 + "\n")

    for req in WRITE_REQUESTS:
        approval_id = str(uuid.uuid4())
        print(f"Write request: apply_firmware_update({req})")
        print(f"  -> QUEUED for human approval (approval_id={approval_id})")
        print(f"     Nothing executes until a human approves or rejects it.\n")


def show_comparison():
    total = len(WRITE_REQUESTS)
    print("\n" + "="*60)
    print("ATTACK SURFACE COMPARISON")
    print("="*60)

    print("\n❌ WITHOUT HITL gate:")
    print(f"  - Write operations executed immediately: {total}/{total}")
    print("  - Human review before execution: NONE")
    print("  - Attacker-supplied bogus firmware version honored: YES")
    print("  - Audit trail of who authorized the change: NONE")

    print("\n✅ WITH HITL gate (MCP02):")
    print(f"  - Write operations paused for approval: {total}/{total}")
    print("  - Human sees proposed action + agent reasoning before deciding: YES")
    print("  - Rejected writes never reach the device API: YES")
    print("  - Every decision logged to the session store: YES")
    print("="*60 + "\n")


if __name__ == "__main__":
    run_without_gate()
    run_with_gate()
    show_comparison()
