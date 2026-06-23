"""
MCP08 — Session Store
----------------------
Stores agent session events for replay and audit.
File-based for local dev — swap for PostgreSQL or Cosmos DB in production.
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path


SESSIONS_DIR = Path("./sessions")


class SessionStore:
    """
    Immutable append-only session log.
    Events can be added but never modified or deleted.
    This is the audit trail property — critical for compliance.
    """

    def __init__(self):
        SESSIONS_DIR.mkdir(exist_ok=True)

    def log_event(
        self,
        session_id: str,
        event_type: str,
        data: Dict[str, Any],
        step: int
    ) -> None:
        """
        Append an event to the session log.
        Events are immutable once written.
        """
        event = {
            "session_id": session_id,
            "step": step,
            "event_type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data
        }

        session_file = SESSIONS_DIR / f"{session_id}.jsonl"

        # Append-only — never overwrite
        with open(session_file, "a") as f:
            f.write(json.dumps(event) + "\n")

        print(f"[SessionStore] Logged: {event_type} (step {step})")

    def get_session(self, session_id: str) -> List[Dict[str, Any]]:
        """
        Retrieve all events for a session in order.
        """
        session_file = SESSIONS_DIR / f"{session_id}.jsonl"

        if not session_file.exists():
            raise ValueError(f"Session {session_id} not found")

        events = []
        with open(session_file, "r") as f:
            for line in f:
                events.append(json.loads(line.strip()))

        return sorted(events, key=lambda e: e["step"])

    def list_sessions(self) -> List[str]:
        """List all recorded sessions."""
        return [f.stem for f in SESSIONS_DIR.glob("*.jsonl")]


# Event types
class EventType:
    AGENT_REASONING = "agent_reasoning"
    TOOL_CALL = "tool_call"
    TOOL_RESPONSE = "tool_response"
    HITL_GATE = "hitl_gate"
    HUMAN_DECISION = "human_decision"
    ACTION_EXECUTED = "action_executed"
    ERROR = "error"
    SESSION_START = "session_start"
    SESSION_END = "session_end"
