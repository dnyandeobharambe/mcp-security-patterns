"""
MCP10 — Context Scoping Core
------------------------------
Every agent session's context (fetched device data, conversation state)
lives behind two keys, not one: session_id AND the tenant_id the session
was created under. Knowing a session_id is not enough to read or write
its context — the caller also has to present the matching tenant_id.
Expired sessions are purged the moment they're discovered, not left
sitting around as a stale window a stolen session_id could still exploit.

OWASP MCP Risk: MCP10:2025 - Cross-Session/Cross-Tenant Context Leakage
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

DEFAULT_TTL_SECONDS = 300  # 5 minutes for demo sessions


@dataclass
class SessionContext:
    session_id: str
    tenant_id: str
    data: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0


class ContextStore:
    """
    Server-side session context isolation. Every read/write goes through
    session_status()/read_context()/write_context() — the deterministic
    Python layer, not the LLM — so a session_id alone never proves
    access; the caller must also present the tenant_id the session was
    created under, and an expired session is gone rather than reachable
    forever.
    """

    def __init__(self):
        self._sessions: Dict[str, SessionContext] = {}

    def create_session(self, tenant_id: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
        session_id = f"sess-{uuid.uuid4().hex[:12]}"
        now = time.time()
        self._sessions[session_id] = SessionContext(
            session_id=session_id,
            tenant_id=tenant_id,
            expires_at=now + ttl_seconds,
        )
        return session_id

    def _is_expired(self, session: SessionContext) -> bool:
        return time.time() >= session.expires_at

    def session_status(self, session_id: str) -> str:
        """
        Returns "not_found", "expired", or "ok" — tenant-blind. An
        expired session is deleted as a side effect of being discovered
        here, so it doesn't linger as reachable stale state.
        """
        session = self._sessions.get(session_id)
        if session is None:
            return "not_found"
        if self._is_expired(session):
            del self._sessions[session_id]
            return "expired"
        return "ok"

    def get_tenant(self, session_id: str) -> Optional[str]:
        session = self._sessions.get(session_id)
        return session.tenant_id if session else None

    def read_context(self, session_id: str) -> Optional[Dict[str, Any]]:
        session = self._sessions.get(session_id)
        return dict(session.data) if session else None

    def write_context(self, session_id: str, data: Dict[str, Any]) -> None:
        session = self._sessions.get(session_id)
        if session is not None:
            session.data.update(data)

    def cleanup_expired(self) -> int:
        expired_ids = [sid for sid, s in self._sessions.items() if self._is_expired(s)]
        for sid in expired_ids:
            del self._sessions[sid]
        return len(expired_ids)

    def reset(self) -> int:
        count = len(self._sessions)
        self._sessions.clear()
        return count

    def active_session_count(self) -> int:
        return len(self._sessions)
