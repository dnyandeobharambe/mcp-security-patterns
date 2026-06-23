"""
MCP03 — Content Sanitization
------------------------------
Checks tool responses for injection patterns before
the agent reasons over them.

OWASP MCP Risk: MCP03:2025 - Tool Poisoning & Malicious Instructions

The attack: malicious content embedded in tool response
hijacks agent decision-making. Agent follows instructions
embedded in data it retrieved — using its own valid credentials.

The defense: sanitize tool responses before returning to agent.
Treat tool output as DATA, not as INSTRUCTIONS.
"""

import re
from typing import Any, Dict, List, Tuple
from enum import Enum


class SanitizationResult(Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    BLOCKED = "blocked"


class ContentSanitizer:
    """
    Checks tool responses for injection patterns.
    Called before tool result is returned to agent context.
    """

    # Patterns that indicate injection attempts
    INJECTION_PATTERNS = [
        # Direct instruction injection
        r"ignore\s+(previous|prior|above|all)\s+instructions?",
        r"forget\s+(everything|all|previous)\s*(instructions?|above)?",
        r"new\s+instructions?:?\s",
        r"system\s*:\s",
        r"<\s*system\s*>",
        r"\[INST\]",
        r"\[SYSTEM\]",

        # Role hijacking
        r"you\s+are\s+now\s+(a\s+)?(new|different|another)",
        r"act\s+as\s+(a\s+)?(different|new|another)",
        r"pretend\s+you\s+are",
        r"your\s+new\s+role\s+is",

        # Credential extraction
        r"(print|output|reveal|show|display|repeat|echo)\s+(your\s+)?(api\s*key|token|secret|password|credential)",
        r"what\s+is\s+your\s+(api\s*key|token|secret|password)",
        r"(api\s*key|token|secret|password)\s*=",

        # Data exfiltration
        r"send\s+(this|the|all)\s+(data|information|content|context)\s+to",
        r"(forward|relay|transmit)\s+(to|the)\s+(email|url|endpoint|server)",
        r"(call|request|fetch|post)\s+(to\s+)?(https?://)",

        # Jailbreak attempts
        r"DAN\s+(mode|prompt)",
        r"jailbreak",
        r"do\s+anything\s+now",
    ]

    # Patterns that are suspicious but not auto-blocked
    SUSPICIOUS_PATTERNS = [
        r"\bINSTRUCTION\b",
        r"\bSYSTEM\b",
        r"\bCOMMAND\b",
        r"\bEXECUTE\b",
        r"http[s]?://[^\s]{20,}",  # Long URLs in data
    ]

    def __init__(self, block_on_suspicious: bool = False):
        """
        block_on_suspicious: if True, block suspicious content too.
        If False, only block confirmed injection patterns.
        """
        self.block_on_suspicious = block_on_suspicious
        self._compiled_injection = [
            re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS
        ]
        self._compiled_suspicious = [
            re.compile(p, re.IGNORECASE) for p in self.SUSPICIOUS_PATTERNS
        ]

    def sanitize(self, content: Any) -> Tuple[SanitizationResult, List[str], Any]:
        """
        Check content for injection patterns.

        Returns:
            (result, findings, sanitized_content)
            - result: CLEAN, SUSPICIOUS, or BLOCKED
            - findings: list of matched patterns
            - sanitized_content: original or sanitized version
        """
        content_str = self._to_string(content)
        findings = []

        # Check for injection patterns — these are blocked
        for pattern in self._compiled_injection:
            matches = pattern.findall(content_str)
            if matches:
                findings.append(f"INJECTION: {pattern.pattern[:50]}... matched: {matches[:2]}")

        if findings:
            return SanitizationResult.BLOCKED, findings, self._redact(content_str, findings)

        # Check for suspicious patterns
        suspicious = []
        for pattern in self._compiled_suspicious:
            matches = pattern.findall(content_str)
            if matches:
                suspicious.append(f"SUSPICIOUS: {pattern.pattern[:50]}... matched: {matches[:2]}")

        if suspicious:
            if self.block_on_suspicious:
                return SanitizationResult.BLOCKED, suspicious, self._redact(content_str, suspicious)
            return SanitizationResult.SUSPICIOUS, suspicious, content

        return SanitizationResult.CLEAN, [], content

    def _to_string(self, content: Any) -> str:
        """Convert any content type to string for scanning."""
        if isinstance(content, str):
            return content
        if isinstance(content, dict):
            return str(content)
        if isinstance(content, list):
            return " ".join(str(item) for item in content)
        return str(content)

    def _redact(self, content: str, findings: List[str]) -> str:
        """Replace blocked content with a safe placeholder."""
        return f"[CONTENT BLOCKED - Potential injection detected. Findings: {len(findings)} pattern(s) matched. Original content removed for safety.]"


def sanitize_tool_response(
    tool_name: str,
    response: Dict[str, Any],
    session_id: str,
    sanitizer: ContentSanitizer = None
) -> Tuple[Dict[str, Any], bool]:
    """
    Sanitize a tool response before returning to agent.

    Returns:
        (sanitized_response, was_blocked)
    """
    if sanitizer is None:
        sanitizer = ContentSanitizer()

    result, findings, sanitized = sanitizer.sanitize(response)

    if result == SanitizationResult.CLEAN:
        print(f"[Sanitizer] {tool_name}: CLEAN")
        return response, False

    elif result == SanitizationResult.SUSPICIOUS:
        print(f"[Sanitizer] {tool_name}: SUSPICIOUS — {len(findings)} finding(s)")
        for f in findings:
            print(f"  → {f}")
        # Return original but log the suspicion
        return response, False

    else:  # BLOCKED
        print(f"[Sanitizer] {tool_name}: BLOCKED — {len(findings)} injection pattern(s)")
        for f in findings:
            print(f"  → {f}")
        # Return safe placeholder
        return {
            "error": "content_blocked",
            "message": "Tool response contained potentially malicious content and was blocked.",
            "tool_name": tool_name,
            "session_id": session_id,
            "findings_count": len(findings)
        }, True
