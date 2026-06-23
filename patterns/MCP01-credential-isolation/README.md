# MCP01 — Credential Isolation

**OWASP MCP Risk:** MCP01:2025 — Token Mismanagement & Secret Exposure

---

## The Attack

An agent connects to an MCP server. The MCP server needs credentials to call
a downstream enterprise API — an ERP system, a device management API, a database.

**Wrong pattern (what most implementations do):**

```
Agent context contains:
{
  "api_key": "sk-prod-abc123...",
  "device_api_url": "https://api.internal.com",
  "instructions": "Check device D-1042 compliance..."
}
```

The credential lives in the agent context. Now:
- It appears in every LangSmith trace
- It appears in every AgentOps session replay
- Anyone with observability dashboard access can read production API keys
- A prompt injection attack can exfiltrate it by asking the agent to repeat its context

**This is MCP01. It's the most common MCP security mistake.**

---

## The Defense — Credential Isolation

Credentials never enter the agent context. Ever.

```
Agent context contains:
{
  "instructions": "Check device D-1042 compliance..."
  # No credentials. None.
}

MCP Server (at execution time):
1. Receives tool call from agent
2. Fetches credential from Key Vault
3. Makes API call with credential
4. Returns result to agent
5. Credential is never logged, never in context
```

The agent gets the result. It never sees the credential.

---

## Attack Demo

Run `attack_demo.py` to see what happens WITHOUT credential isolation:

```bash
python attack_demo.py
```

You will see the API key appear in the agent's reasoning trace —
exactly what an attacker harvesting observability logs would find.

---

## Pattern Demo

Run `server.py` and `client.py` to see credential isolation working:

```bash
# Terminal 1 — start the secure MCP server
python server.py

# Terminal 2 — run the client
python client.py
```

The agent will check device compliance. The API key will never appear
in any log, trace, or agent context.

---

## How It Works

```
client.py (agent)          server.py (MCP server)       Key Vault
     |                           |                           |
     |-- tool_call("check_device", {"device_id": "D-1042"}) |
     |                           |                           |
     |                           |-- get_secret("api-key") ->|
     |                           |<- "sk-prod-abc123..."  ---|
     |                           |                           |
     |                           |-- API call with credential
     |                           |<- device state response
     |                           |                           |
     |<- {"status": "compliant", "firmware": "2.4.1"}       |
     |                           |                           |
  Credential never crosses this boundary
```

---

## Key Code Pattern

```python
# server.py — credential injected at execution time
@app.post("/tools/check_device")
async def check_device(request: ToolRequest):
    # Credential fetched HERE — never stored in agent context
    api_key = await key_vault.get_secret("device-api-key")

    # Use credential to call enterprise API
    result = await device_api.get_device_state(
        device_id=request.params["device_id"],
        api_key=api_key  # Used here, not stored
    )

    # Return RESULT only — credential stays server-side
    return {"status": result.compliance_status}
```

---

## Files

- `server.py` — MCP server with credential isolation pattern
- `client.py` — Agent that calls the MCP server (no credentials in context)
- `attack_demo.py` — Shows what happens WITHOUT this pattern
- `mock_key_vault.py` — Local mock for testing without Azure
- `requirements.txt` — Dependencies
