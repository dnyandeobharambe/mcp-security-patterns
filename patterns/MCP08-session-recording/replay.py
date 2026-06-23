"""
MCP08 — Session Replay
------------------------
Reconstruct any agent session from the audit log.
Shows every step in sequence — what the agent saw, decided, and did.

Usage:
    python replay.py <session-id>
    python replay.py --list
"""

import sys
import json
from datetime import datetime
from session_store import SessionStore, EventType


store = SessionStore()

EVENT_ICONS = {
    EventType.SESSION_START: "🚀",
    EventType.AGENT_REASONING: "🧠",
    EventType.TOOL_CALL: "🔧",
    EventType.TOOL_RESPONSE: "📥",
    EventType.HITL_GATE: "👤",
    EventType.HUMAN_DECISION: "✅",
    EventType.ACTION_EXECUTED: "⚡",
    EventType.SESSION_END: "🏁",
    EventType.ERROR: "❌",
}


def replay_session(session_id: str):
    """Replay a full session in chronological order."""

    print(f"\n{'='*60}")
    print(f"SESSION REPLAY: {session_id}")
    print(f"{'='*60}\n")

    try:
        events = store.get_session(session_id)
    except ValueError as e:
        print(f"Error: {e}")
        return

    for event in events:
        icon = EVENT_ICONS.get(event["event_type"], "📌")
        timestamp = event["timestamp"]
        event_type = event["event_type"]
        step = event["step"]
        data = event["data"]

        print(f"Step {step:02d} | {timestamp} | {icon} {event_type.upper()}")
        print(f"{'─'*60}")

        if event_type == EventType.SESSION_START:
            print(f"  Goal: {data.get('goal', 'N/A')}")

        elif event_type == EventType.AGENT_REASONING:
            print(f"  Reasoning: {data.get('reasoning', 'N/A')}")

        elif event_type == EventType.TOOL_CALL:
            print(f"  Tool: {data.get('tool_name')}")
            print(f"  Params: {json.dumps(data.get('params', {}), indent=4)}")

        elif event_type == EventType.TOOL_RESPONSE:
            print(f"  Tool: {data.get('tool_name')}")
            print(f"  Result: {json.dumps(data.get('result', {}), indent=4)}")

        elif event_type == EventType.HITL_GATE:
            print(f"  Proposed action: {data.get('proposed_action')}")
            print(f"  Reviewer: {data.get('reviewer')}")
            print(f"  Status: PENDING HUMAN DECISION")

        elif event_type == EventType.HUMAN_DECISION:
            print(f"  Decision: {data.get('decision')}")
            print(f"  By: {data.get('authorized_by')}")
            print(f"  Reason: {data.get('reason', 'N/A')}")

        elif event_type == EventType.ACTION_EXECUTED:
            print(f"  Action: {data.get('action')}")
            print(f"  Params: {json.dumps(data.get('params', {}), indent=4)}")
            print(f"  Authorized by: {data.get('authorized_by')}")

        elif event_type == EventType.SESSION_END:
            print(f"  Outcome: {data.get('outcome')}")
            print(f"  Summary: {data.get('summary')}")

        elif event_type == EventType.ERROR:
            print(f"  Error: {data.get('error')}")
            print(f"  Context: {data.get('context', 'N/A')}")

        print()

    print(f"{'='*60}")
    print(f"Total steps: {len(events)}")
    print(f"{'='*60}\n")


def list_sessions():
    """List all available sessions."""
    sessions = store.list_sessions()
    if not sessions:
        print("No sessions recorded yet.")
        return

    print(f"\nRecorded sessions ({len(sessions)}):")
    for s in sessions:
        print(f"  - {s}")
    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python replay.py <session-id>")
        print("       python replay.py --list")
        sys.exit(1)

    if sys.argv[1] == "--list":
        list_sessions()
    else:
        replay_session(sys.argv[1])
