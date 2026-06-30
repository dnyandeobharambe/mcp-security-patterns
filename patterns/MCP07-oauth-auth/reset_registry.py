"""
reset_registry.py — Clear all registered agent identities and the nonce
cache on the MCP07 server.

Usage:
    python reset_registry.py

What it does:
    1. Sends DELETE /reset to the running MCP07 server (must be up on :8007)
    2. The server clears its in-memory agent registry and used-nonce cache
    3. Prints how many entries were cleared, so the demo can be re-run
       from a clean slate without restarting the server

Example output:
    Cleared 3 entries
    Ready for new demo
"""

import httpx


MCP_SERVER_URL = "http://localhost:8007"


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
