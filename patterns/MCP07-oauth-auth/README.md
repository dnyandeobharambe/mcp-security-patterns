# MCP07 — AAuth Agent Identity & Request Signing

**OWASP MCP Risk:** MCP07:2025 — Insecure Credential & Identity Management

**Reference:** Dick Hardt's AAuth protocol spec, implemented per
[github.com/christian-posta/aauth-full-demo](https://github.com/christian-posta/aauth-full-demo)

---

## The Domain

Same fleet as the rest of this repo: a telecom operator running 5,000+
field devices — gateways, base station controllers, edge routers. An
agent calls MCP tools against that fleet — `check_device_compliance`,
`apply_firmware_update` — the same tools MCP01 and MCP02 protect.

Those patterns assume the caller's *identity* is already established —
MCP01 isolates the credential the server uses downstream, MCP02 gates
the write itself. MCP07 sits in front of both: it answers a question
neither of them asks — **is the caller even who it claims to be?**

---

## The Attack

An agent authenticates to the MCP server with a bearer token — a static
string sent on every request.

```
Agent sends:  Authorization: Bearer sk-agent-prod-7f3a9c2e1b8d
```

That header line gets written wherever the request passes through:

- A request log on the MCP server
- An APM trace (Datadog, New Relic, OpenTelemetry span attributes)
- A reverse proxy's access log
- Anywhere the agent's HTTP client logs outgoing headers for debugging

**Anyone who can read any one of those captures the entire credential.**
They paste it into a request from a completely different machine:

```
Attacker sends:  Authorization: Bearer sk-agent-prod-7f3a9c2e1b8d
```

The server has no way to tell this apart from the legitimate agent. The
token *is* the identity — whoever holds the string passes. There's no
signal in the request that distinguishes "the agent fleet controller"
from "a script kiddie who grepped a proxy log."

**This is MCP07. A bearer token conflates "data that was transmitted"
with "proof of identity" — and anything transmitted can be copied.**

---

## The Defense — AAuth: Cryptographic Identity, Signed Requests

Every agent generates an Ed25519 keypair. **The private key never leaves
the agent process** — not in a request, not in a log, not anywhere.
Instead of sending a secret, the agent signs each request with it:

```
Agent identity:        a keypair, not a string
Request sent:           method + path + agent_id + timestamp + nonce
                         + body-digest, signed with the private key
Authorization header:   NONE — there is nothing to send that proves
                         identity by itself
```

The server verifies the signature against the agent's previously
registered **public** key — public keys are safe to log, safe to leak,
useless to an attacker on their own. Two more checks close the gaps a
signature alone doesn't cover:

- **Timestamp window (±120s)** — rejects stale or long-delayed replays
- **Nonce cache** — rejects a captured request replayed verbatim, even
  if it's replayed within the timestamp window

This mirrors HTTP Message Signatures (RFC 9421) and the proof-of-possession
model from Dick Hardt's AAuth spec — see
[Simplifications vs. Real AAuth](#simplifications-vs-real-aauth) below for
what's trimmed for this demo.

### Both attack variants AAuth defeats

**(a) Verbatim replay** — the attacker captures a complete, validly
signed request and resends it exactly as captured.
→ Blocked by **nonce reuse detection**: the nonce was already recorded
the first time the request was verified, so a second submission with
the same `(agent_id, nonce)` pair is rejected outright.

**(b) Tamper-in-flight** — the attacker intercepts a request before
it's processed and rewrites the body (e.g. swaps a read-only tool call
for a write, or changes `target_version`) while keeping the original
signature.
→ Blocked because **the signature covers the body**: the canonical
string that was signed includes a SHA-256 digest of the original body.
Any change to the body produces a different digest, the signature no
longer matches, and verification fails — and the attacker has no
private key to produce a new, valid signature over the modified body.

Even a full request capture — every header, the entire payload — gets
an attacker exactly one thing: a signature that is already spent, bound
to a body it can no longer be paired with.

---

## Attack Demo — Real Output

Run `attack_demo.py` — no server needed, it's self-contained:

```bash
python attack_demo.py
```

Actual console output:

```
⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️
VULNERABLE PATTERN — BEARER TOKEN — DO NOT USE IN PRODUCTION
⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️

Legitimate agent calls the legacy MCP server:
  Authorization: Bearer sk-agent-prod-7f3a9c2e1b8d
  -> {'device_id': 'D-1042', 'compliance': 'NON_COMPLIANT', 'firmware': '2.3.1'}

That exact header line gets written to a request log / APM trace / proxy.
An attacker with read access to that log captures the full token.

Attacker replays the EXACT same token from a different machine:
  Authorization: Bearer sk-agent-prod-7f3a9c2e1b8d
  -> {'device_id': 'D-1099', 'compliance': 'NON_COMPLIANT', 'firmware': '2.3.1'}
  Server treats attacker as the legitimate agent: True


✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅
WITH AAuth — MCP07 Pattern
✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅

Legitimate agent identity registered: agent-fleet-ops
Public key on file: 0c1133972f21cf00... (private key never leaves the agent)

Legitimate agent sends a signed request:
  {
  "X-Aauth-Agent-Id": "agent-fleet-ops",
  "X-Aauth-Timestamp": "1782846145",
  "X-Aauth-Nonce": "e5c346e91a00ea046066e64469338cd5",
  "X-Aauth-Signature": "n8RvPcf1fhjcQo/r8hP9fEPRJlhYHl6f8EKEYVChq0383ZtM2wM1gm/t1sgqu9XkmH5U6AlrSRdWJoBue4jwDg=="
}
  -> verified=True, agent=agent-fleet-ops

Attacker captures the ENTIRE request off the wire — headers AND body.
There is no static secret in it, only a one-time-use proof of possession.

Attack 2a: Attacker replays the captured request verbatim.
  -> verified=False, reason='nonce already used — replay detected'
  Blocked by: nonce reuse detection

Attack 2b: Attacker intercepts a second, not-yet-submitted signed request
in flight and rewrites the body to escalate to a write tool before forwarding it.
  -> verified=False, reason='signature verification failed — request was tampered with or forged'
  Blocked by: signature covers the body — changing it invalidates the signature
  Attacker has no private key, so they cannot re-sign and try again


============================================================
ATTACK SURFACE COMPARISON
============================================================

❌ Bearer token (no AAuth):
  - Stolen token reusable indefinitely: YES
  - Stolen token reusable from any machine: YES
  - Attacker can call ANY tool with a stolen token: YES
  - Detectable as theft vs. legitimate use: NO

✅ AAuth signed requests (MCP07):
  - Stolen request replayable: NO (nonce reuse detected)
  - Stolen request repurposable for a new action: NO (signature covers body)
  - Forging a new request without the private key: IMPOSSIBLE
  - What an attacker gains from a full request capture: one already-used, now-dead proof
============================================================
```

---

## Pattern Demo

```bash
# Terminal 1 — start the secure MCP server
python server.py

# Terminal 2 — run the legitimate agent
python client.py

# Terminal 2 — verify every check (server must still be running)
python test_mcp07.py

# Terminal 2 — reset in-memory state for a clean re-run
python reset_registry.py
```

`client.py` generates an Ed25519 identity, registers the public key with
the server, then signs and sends two tool calls. Watch the server logs —
no `Authorization` header is ever read, only `[AAuth] Verified request
from agent: ...`.

**Test result:**
```
Test 1: Valid signed request succeeds                              ✅ 200
Test 2: Unregistered agent identity is rejected                    ✅ 401
Test 3: Tampering with the body invalidates the signature          ✅ 401
Test 4: Replaying an already-used signed request is rejected       ✅ 401
Test 5: A bare bearer-style call with no AAuth headers is rejected ✅ 401
Test 6: A stale timestamp outside the clock-skew window is rejected ✅ 401
Results: 6/6 passed
```

---

## How It Works

```
client.py (agent)              server.py (MCP server)
     |                               |
     |-- generate Ed25519 keypair    |
     |   (private key stays local)   |
     |                               |
     |-- POST /agents/register ----->|
     |   {agent_id, public_key_hex}  |-- store public key in registry
     |                               |
     |-- sign(method,path,agent_id,  |
     |        timestamp,nonce,       |
     |        body-digest)           |
     |                               |
     |-- POST /tools/call ---------->|
     |   X-Aauth-Agent-Id            |-- look up public key for agent_id
     |   X-Aauth-Timestamp           |-- check timestamp within ±120s
     |   X-Aauth-Nonce               |-- check nonce not already used
     |   X-Aauth-Signature           |-- verify signature against canonical string
     |                               |
     |<- {result, authenticated_agent} |
     |                               |
  Private key never crosses this boundary — only proofs derived from it
```

---

## Key Code Pattern

```python
# aauth.py — server-side verification, no shared secret involved
def verify_request(registry, nonces, method, path, headers, body):
    agent_id = headers.get("X-Aauth-Agent-Id")
    public_key = registry.get_public_key(agent_id)        # public only
    if public_key is None:
        return False, None, f"unknown agent identity: {agent_id}"

    if abs(time.time() - int(headers["X-Aauth-Timestamp"])) > MAX_CLOCK_SKEW_SECONDS:
        return False, None, "timestamp outside allowed window"

    if nonces.seen_before(agent_id, headers["X-Aauth-Nonce"]):
        return False, None, "nonce already used — replay detected"

    canonical = _canonical_string(method, path, agent_id,
                                   headers["X-Aauth-Timestamp"],
                                   headers["X-Aauth-Nonce"], body)
    public_key.verify(base64.b64decode(headers["X-Aauth-Signature"]), canonical)
    nonces.record(agent_id, headers["X-Aauth-Nonce"])
    return True, agent_id, "ok"
```

---

## Simplifications vs. Real AAuth

This pattern demonstrates the core proof-of-possession property of AAuth
without standing up a full implementation:

- **JWKS discovery** is replaced with direct `POST /agents/register` —
  real AAuth fetches public keys from a `/.well-known/aauth-agent`
  endpoint (the JWKS scheme), or accepts a key embedded in the request
  itself (the HWK scheme for pseudonymous identity)
- **No agent-to-agent token exchange** — real AAuth supports chained
  delegation (Backend → Agent A → Agent B) via resource tokens issued on
  401; this demo covers a single agent calling a single server
- **No user-delegated JWTs** — real AAuth also issues `aa-auth+jwt`
  tokens from a Person Server for user-authorized actions; this demo
  focuses purely on agent-to-server proof of possession

---

## Files

- `aauth.py` — core protocol: agent identity, signing, verification, nonce cache
- `server.py` — MCP server with AAuth-gated tool calls
- `client.py` — agent that generates an identity, registers it, and signs every call
- `attack_demo.py` — bearer-token theft succeeding vs. AAuth request capture failing
- `test_mcp07.py` — verifies valid/tampered/replayed/unregistered/stale/missing-header cases
- `reset_registry.py` — clears registered agents and the nonce cache for a fresh demo run

---

**What an attacker gains from a full request capture: one already-used,
now-dead proof.**
