"""
reset_registry.py — Clear the call audit log on the MCP09 server.

Usage:
    python reset_registry.py

What it does:
    1. Sends DELETE /reset to the running MCP09 server (must be up on :8009)
    2. The server clears its in-memory call log
    3. Prints how many entries were cleared, so the demo can be re-run
       from a clean slate without restarting the server

Note: role allowlists are policy, not demo state — reset does not touch
them. Re-running the demo always starts from the same authorization rules.

Example output:
    Cleared 4 entries
    Ready for new demo
"""

import httpx


MCP_SERVER_URL = "http://localhost:8009"


def reset_registry() -> dict:
    response = httpx.delete(f"{MCP_SERVER_URL}/reset", timeout=30.0)
    response.raise_for_status()
    return response.json()


def main():
    result = reset_registry()
    print(f"\nCleared {result['cleared']} entries")
    print(f"{result['message']}\n")


if __name__ == "__main__":
    main()
