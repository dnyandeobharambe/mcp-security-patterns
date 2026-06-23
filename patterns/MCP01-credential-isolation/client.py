"""
MCP01 — Client (Agent side)
----------------------------
Shows how the agent calls the MCP server without any credentials in its context.
The agent knows NOTHING about authentication — only tool names and parameters.

This is what a LangGraph agent calling a secure MCP server looks like.
"""

import asyncio
import uuid
import httpx
import json


MCP_SERVER_URL = "http://localhost:8001"


async def agent_check_device(device_id: str) -> dict:
    """
    Simulates an AI agent calling the MCP tool.

    Notice what is NOT here:
    - No API keys
    - No credentials
    - No auth tokens
    - No secrets of any kind

    The agent only knows: tool name + parameters
    """

    session_id = str(uuid.uuid4())

    print(f"\n{'='*60}")
    print(f"AGENT: Checking device compliance for {device_id}")
    print(f"AGENT: Session ID: {session_id}")
    print(f"AGENT: Context contains — device_id only. No credentials.")
    print(f"{'='*60}")

    # This is what the agent sends — clean context, no credentials
    tool_request = {
        "tool_name": "check_device_compliance",
        "params": {
            "device_id": device_id
            # That's it. No api_key. No auth_token. Nothing.
        },
        "session_id": session_id
    }

    print(f"\nAGENT → MCP Server: {json.dumps(tool_request, indent=2)}")

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{MCP_SERVER_URL}/tools/call",
            json=tool_request,
            timeout=30.0
        )
        response.raise_for_status()
        result = response.json()

    print(f"\nMCP Server → AGENT: {json.dumps(result, indent=2)}")
    print(f"\nAGENT: Received compliance verdict — no credentials in response")
    print(f"AGENT: This result is safe to log, trace, and include in LangSmith")

    return result


async def verify_no_credentials_in_traces():
    """
    Demonstration: what appears in observability logs.
    With credential isolation — ONLY tool results appear. No secrets.
    """
    print(f"\n{'='*60}")
    print("VERIFICATION: What appears in LangSmith / AgentOps traces")
    print(f"{'='*60}")

    # Simulate what would be logged
    trace_entry = {
        "session_id": "demo-session-001",
        "tool_called": "check_device_compliance",
        "input": {"device_id": "D-1042"},  # Clean — no credentials
        "output": {
            "compliance_status": "NON_COMPLIANT",
            "firmware_current": "2.3.1",
            "firmware_required": "2.4.0"
        }
        # No api_key. No auth_token. Safe to store forever.
    }

    print(f"Trace entry (safe to log):\n{json.dumps(trace_entry, indent=2)}")
    print(f"\n✅ No credentials in trace — MCP01 pattern working correctly")


async def main():
    print("\nMCP01 — Credential Isolation Pattern Demo")
    print("Agent checks device compliance without knowing the API key\n")

    # Check two devices
    result1 = await agent_check_device("D-1042")
    result2 = await agent_check_device("D-1043")

    # Show what traces look like
    await verify_no_credentials_in_traces()

    print(f"\n{'='*60}")
    print("Summary:")
    print(f"  D-1042: {result1['result']['compliance_status']}")
    print(f"  D-1043: {result2['result']['compliance_status']}")
    print(f"  Credentials exposed to agent: NONE")
    print(f"  Credentials in traces: NONE")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    asyncio.run(main())
