"""
reset_context.py — Clear all session context on the MCP10 server.

Usage:
    python reset_context.py

What it does:
    1. Sends DELETE /reset to the running MCP10 server (must be up on :8010)
    2. The server clears every in-memory session and its context
    3. Prints how many sessions were cleared, so the demo can be re-run
       from a clean slate without restarting the server

Example output:
    Cleared 3 sessions
    Ready for new demo
"""

import httpx


MCP_SERVER_URL = "http://localhost:8010"


def reset_context() -> dict:
    response = httpx.delete(f"{MCP_SERVER_URL}/reset", timeout=30.0)
    response.raise_for_status()
    return response.json()


def main():
    result = reset_context()
    print(f"\nCleared {result['cleared']} sessions")
    print(f"{result['message']}\n")


if __name__ == "__main__":
    main()
