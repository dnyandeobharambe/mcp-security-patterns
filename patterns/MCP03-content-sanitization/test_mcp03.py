"""
MCP03 — Content Sanitization Test
-----------------------------------
Run this to test the content sanitization pattern.
Make sure server.py is running first in another terminal.

Usage:
    python test_mcp03.py
"""

import httpx
import asyncio
import json


MCP_SERVER_URL = "http://localhost:8003"

# Test cases — mix of clean and malicious documents
TEST_DOCUMENTS = [
    ("DOC-001", "Clean document — should pass"),
    ("DOC-002", "Contains injection — should be BLOCKED"),
    ("DOC-003", "Clean meeting notes — should pass"),
    ("DOC-004", "Contains SYSTEM instruction — should be BLOCKED"),
]


async def test_document(client: httpx.AsyncClient, doc_id: str, description: str) -> dict:
    """Test a single document retrieval."""
    response = await client.post(
        f"{MCP_SERVER_URL}/tools/call",
        json={
            "tool_name": "get_document",
            "params": {"doc_id": doc_id},
            "session_id": "test-session-001",
            "step": 1
        }
    )
    response.raise_for_status()
    return response.json()


async def main():
    print("\n" + "="*60)
    print("MCP03 — Content Sanitization Test")
    print("="*60)
    print("Testing document retrieval with injection detection\n")

    passed = 0
    failed = 0

    async with httpx.AsyncClient() as client:
        for doc_id, description in TEST_DOCUMENTS:
            print(f"Testing {doc_id}: {description}")

            result = await test_document(client, doc_id, description)
            blocked = result.get("sanitized", False)
            status = "BLOCKED" if blocked else "CLEAN"

            # Expected results
            expected_blocked = doc_id in ["DOC-002", "DOC-004"]
            correct = blocked == expected_blocked

            icon = "✅" if correct else "❌"
            print(f"  {icon} Result: {status} | Expected: {'BLOCKED' if expected_blocked else 'CLEAN'}")

            if not blocked:
                content = result.get("result", {}).get("content", "")
                print(f"  Content preview: {content[:80]}...")
            else:
                print(f"  Blocked content replaced with safe placeholder")

            print()

            if correct:
                passed += 1
            else:
                failed += 1

    print("="*60)
    print(f"Results: {passed} passed, {failed} failed")
    print("="*60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
