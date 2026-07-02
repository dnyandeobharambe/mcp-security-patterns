"""
reset_verification.py — Clear the audit log and revert the manifest to
its baseline on the MCP04 server.

Usage:
    python reset_verification.py

What it does:
    1. Sends DELETE /reset to the running MCP04 server (must be up on :8004)
    2. The server clears its in-memory publish/load audit log and reverts
       the manifest to its two baseline tools (compliance_checker,
       firmware_validator) — any entries published during a demo run
       (legitimate or forged) are discarded
    3. Prints how many audit entries were cleared, so the demo can be
       re-run from a clean slate without restarting the server

Example output:
    Cleared 6 entries
    Ready for new demo
"""

import httpx


MCP_SERVER_URL = "http://localhost:8004"


def reset_verification() -> dict:
    response = httpx.delete(f"{MCP_SERVER_URL}/reset", timeout=30.0)
    response.raise_for_status()
    return response.json()


def main():
    result = reset_verification()
    print(f"\nCleared {result['cleared']} entries")
    print(f"{result['message']}\n")


if __name__ == "__main__":
    main()
