"""
MCP09 — Tool Registry Core
------------------------------
A deny-by-default catalog of every tool an MCP server exposes, plus a
per-role allowlist deciding which of those tools each agent identity may
call. An agent calling a tool that exists but isn't on its role's
allowlist is rejected — same as an agent calling a tool that was never
registered at all.

OWASP MCP Risk: MCP09:2025 - Rogue/Unverified MCP Servers & Tools
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class ToolSpec:
    name: str
    description: str
    sensitivity: str  # "read" | "write" | "admin"


# The full catalog of tools this MCP server knows how to execute.
# Being in this catalog is necessary but not sufficient to call a tool —
# the caller's role also has to allow it. A tool NOT in this catalog
# (a typo, a deprecated name, a name an attacker guessed) is rejected
# before role checks even run.
TOOL_CATALOG: Dict[str, ToolSpec] = {
    "check_compliance": ToolSpec(
        "check_compliance", "Read-only device compliance check.", "read"
    ),
    "get_device_status": ToolSpec(
        "get_device_status", "Read-only device status/uptime lookup.", "read"
    ),
    "apply_firmware_update": ToolSpec(
        "apply_firmware_update", "Schedules a firmware update for one device.", "write"
    ),
    "export_all_device_data": ToolSpec(
        "export_all_device_data",
        "Shadow tool — bulk-exports EVERY device's data in one call. "
        "Not meant to be reachable by routine fleet agents.",
        "admin",
    ),
    "admin_reset_device": ToolSpec(
        "admin_reset_device",
        "Factory-resets a device, wiping its configuration. Destructive.",
        "admin",
    ),
}


# Per-role allowlists. Deny by default: a role not listed here gets the
# empty set, and a tool not listed under a role is unreachable by it —
# regardless of whether the tool exists in TOOL_CATALOG.
ROLE_ALLOWLISTS: Dict[str, Set[str]] = {
    "compliance-agent": {"check_compliance", "get_device_status"},
    "fleet-ops-agent": {"check_compliance", "get_device_status", "apply_firmware_update"},
    "fleet-admin-agent": {
        "check_compliance",
        "get_device_status",
        "apply_firmware_update",
        "export_all_device_data",
        "admin_reset_device",
    },
}


# Demo agent identities, pre-assigned to a role. In production this
# mapping would come from MCP07-verified agent identity, not a static
# table — registry lookups here stand in for that.
AGENT_ROLES: Dict[str, str] = {
    "compliance-agent-001": "compliance-agent",
    "fleet-ops-agent-001": "fleet-ops-agent",
    "fleet-admin-agent-001": "fleet-admin-agent",
}


@dataclass
class CallRecord:
    agent_id: str
    tool_name: str
    allowed: bool
    reason: str


class ToolRegistry:
    """
    Server-side allowlist enforcement. Every authorization decision goes
    through is_allowed() — the deterministic Python layer, not the LLM —
    so a tool call either matches an explicit allowlist entry or it's
    rejected, with no implicit trust extended either way.
    """

    def __init__(self):
        self._agent_roles: Dict[str, str] = dict(AGENT_ROLES)
        self._call_log: List[CallRecord] = []

    def get_role(self, agent_id: str) -> Optional[str]:
        return self._agent_roles.get(agent_id)

    def is_known_tool(self, tool_name: str) -> bool:
        return tool_name in TOOL_CATALOG

    def is_allowed(self, agent_id: str, tool_name: str) -> bool:
        role = self.get_role(agent_id)
        if role is None:
            return False
        return tool_name in ROLE_ALLOWLISTS.get(role, set())

    def get_allowed_tools(self, agent_id: str) -> List[str]:
        role = self.get_role(agent_id)
        if role is None:
            return []
        return sorted(ROLE_ALLOWLISTS.get(role, set()))

    def register_agent(self, agent_id: str, role: str) -> None:
        self._agent_roles[agent_id] = role

    def log_call(self, agent_id: str, tool_name: str, allowed: bool, reason: str) -> None:
        self._call_log.append(CallRecord(agent_id, tool_name, allowed, reason))

    def get_call_log(self) -> List[CallRecord]:
        return list(self._call_log)

    def reset_call_log(self) -> int:
        count = len(self._call_log)
        self._call_log.clear()
        return count
