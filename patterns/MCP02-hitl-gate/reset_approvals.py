"""
reset_approvals.py — Clear all pending/decided approval state on the MCP02 server.

Usage:
    python reset_approvals.py

What it does:
    1. Sends DELETE /approvals/reset to the running MCP02 server (must be up on :8002)
    2. The server clears its in-memory approval queue — both pending and
       already-decided entries
    3. Prints how many approvals were cleared, so the demo can be re-run
       from a clean slate without restarting the server

Example output:
    Cleared 1 pending approval(s)
    Ready for new demo
"""

import httpx


MCP_SERVER_URL = "http://localhost:8002"


def reset_approvals() -> dict:
    response = httpx.delete(f"{MCP_SERVER_URL}/approvals/reset", timeout=30.0)
    response.raise_for_status()
    return response.json()


def main():
    result = reset_approvals()
    print(f"\nCleared {result['cleared']} pending approval(s)")
    print(f"{result['message']}\n")


if __name__ == "__main__":
    main()
