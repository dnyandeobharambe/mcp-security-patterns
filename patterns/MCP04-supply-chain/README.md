# MCP04 — Supply Chain Verification

**OWASP MCP Risk:** MCP04:2025 — Supply Chain Vulnerabilities (via MCP)

---

## The Domain

Same fleet as the rest of this repo: a telecom operator running 5,000+
field devices. Agents don't just call tools an MCP server hard-codes —
they load tool implementations that were built and shipped by someone
else (an internal team, a vendor, an open-source package). Every other
pattern in this repo asks "is this caller allowed to do this?"
([MCP09](../MCP09-tool-registry/)) or "is this session's data scoped
correctly?" ([MCP10](../MCP10-context-scoping/)). MCP04 asks a question
those patterns don't cover at all: **is the tool itself the thing it
claims to be?**

---

## The Attack

An agent is pointed at a tool called `compliance_checker_v2` — a
plausible name, sitting right next to the real `compliance_checker`.
Nothing hashes it. Nothing checks who published it. It loads and runs
exactly like any other tool:

```
compliance_checker    -> {'device_id': 'D-1042', 'compliance': 'NON_COMPLIANT'}   # real
compliance_checker_v2 -> {'device_id': 'D-1042', 'compliance': 'NON_COMPLIANT'}   # backdoored
```

The two outputs are identical. That's the point — the backdoored tool
returns a completely normal-looking compliance result **and**, in the
same call, silently exfiltrates every device's data to an external
endpoint. There is no error, no unusual response shape, nothing an
agent (or a human skimming logs) would flag. A second, subtler version
of the same attack doesn't even need a new name: an attacker swaps
tampered bytes in **under the real `compliance_checker` name**, so a
caller who only checks "did I get a tool named `compliance_checker`"
still gets compromised.

**This is MCP04. An MCP server with no supply chain verification has no
notion of "this artifact is the one that was actually approved" —
only "a tool with this name produced a response that looks right."**

---

## The Defense — Signed Manifest, Verified at Two Points

Two structures, checked at two different times, before any tool handler runs:

```
TOOL_MANIFEST        — per tool: which publisher shipped it, and the
                        sha256 hash of the exact artifact bytes that
                        were approved
APPROVED_PUBLISHERS   — publisher_id -> Ed25519 public key, held
                        server-side, never supplied by a request
```

**Gate 1 — publishing a manifest entry** (`POST /manifest/publish`):
a new or replacement entry is only accepted if it carries a signature
that verifies against an *approved* publisher's public key.

```
1. publisher_id is in APPROVED_PUBLISHERS       -> else rejected (unapproved_publisher)
2. signature verifies against that public key,
   over sha256(artifact)                        -> else rejected (invalid_signature)
```

**Gate 2 — loading a tool to execute it** (`POST /tools/call`):
the submitted artifact's hash must match what the manifest recorded.

```
1. tool_name exists in the manifest             -> else rejected (unknown_tool)
2. sha256(artifact) == manifest's expected_hash  -> else rejected (hash_mismatch)
```

Claiming to be `acme-security` in a publish request is not enough —
the caller has to actually hold `acme-security`'s private key. And
having a tool_name the manifest recognizes is not enough either — the
bytes about to execute have to be byte-for-byte what was approved.
Every publish and load attempt, successful or not, is written to an
audit log with its verification outcome.

---

## Attack Demo — Real Output

Run `attack_demo.py` — no server needed, it's self-contained:

```bash
python attack_demo.py
```

Actual console output:

```
⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️
VULNERABLE PATTERN — NO SUPPLY CHAIN VERIFICATION — DO NOT USE IN PRODUCTION
⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️

Agent loads the real compliance_checker tool:
  -> {'device_id': 'D-1042', 'compliance': 'NON_COMPLIANT'}

Agent is pointed at 'compliance_checker_v2' — plausible name, never audited.
Nothing hashes it, nothing checks who published it, nothing stops it from loading:
  [BACKDOOR] silently POSTing 3 device records to http://attacker.example/collect
  -> {'device_id': 'D-1042', 'compliance': 'NON_COMPLIANT'}
  The returned result is indistinguishable from the legitimate tool's output —
  the exfiltration happened silently in the same call.


✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅
WITH Supply Chain Verification — MCP04 Pattern
✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅

Legitimate tool, correct artifact bytes -> loads and executes:
  verify_and_load(compliance_checker, <approved artifact>) -> ok=True, code=ok

Attacker tries the backdoored tool under its own name:
  verify_and_load(compliance_checker_v2, <backdoored artifact>) -> ok=False, code=unknown_tool
  Blocked by: 'compliance_checker_v2' is not in the tool manifest

Attacker instead reuses the LEGITIMATE tool_name but swaps in the backdoored bytes:
  verify_and_load(compliance_checker, <backdoored artifact under real name>) -> ok=False, code=hash_mismatch
  Blocked by: artifact hash 7364922a2b18... does not match manifest hash ef40abf174c6... — artifact tampered since publish

Attacker tries to PUBLISH the backdoored tool as a new manifest entry, claiming
to be the trusted publisher 'acme-security' — but signs it with their own key:
  publish(compliance_checker_v2, claimed_publisher=acme-security, <forged sig>) -> ok=False, code=invalid_signature
  Blocked by: signature does not verify against publisher 'acme-security''s key — manifest entry forged or corrupted


============================================================
ATTACK SURFACE COMPARISON
============================================================

❌ No supply chain verification:
  - Any tool_name the agent is pointed at executes: YES
  - Backdoored tool indistinguishable from real one by its output: YES
  - Tampered artifact under a known tool name executes: YES
  - Forged manifest entry claiming a trusted publisher accepted: YES

✅ Supply chain verification (MCP04):
  - Unregistered tool name: rejected (unknown_tool), before execution
  - Tampered artifact under a real tool name: rejected (hash_mismatch)
  - Manifest entry forged under a trusted publisher's name: rejected (invalid_signature)
  - Every publish and load attempt: logged with its verification outcome
============================================================
```

---

## Pattern Demo

```powershell
# Terminal 1 — start the secure MCP server
python server.py

# Terminal 2 — run the legitimate agent
python client.py

# Terminal 2 — verify every check (server must still be running)
python test_mcp04.py

# Terminal 2 — reset audit log + manifest to baseline for a clean re-run
python reset_verification.py
```

`client.py` loads the verified `compliance_checker` tool successfully,
then attempts the same two attacks from the attack demo against the
live server, and is rejected both times.

**Test result:**
```
Test 1: Verified tool loads and executes successfully                ✅ 200
Test 2: Tool with wrong hash rejected before execution                ✅ 409
Test 3: Unknown tool not in manifest rejected                         ✅ 404
Test 4: Tool with invalid signature rejected                          ✅ 401
Test 5: Tampered tool detected even with correct name                 ✅ 409
Test 6: Audit log captures every load attempt                         ✅
Results: 6/6 passed
```

---

## How It Works

```
client.py (agent)                       server.py (MCP server)
     |                                        |
     |-- POST /manifest/publish ------------->|
     |   {tool_name, publisher_id,             |-- publisher_id approved?    -> 403 if not
     |    artifact, signature_hex}             |-- signature verifies?       -> 401 if not
     |                                         |-- store manifest entry
     |<- {status, expected_hash} -------------|
     |                                        |
     |-- POST /tools/call -------------------->|
     |   {tool_name, artifact, params}         |-- tool_name in manifest?    -> 404 if not
     |                                         |-- sha256(artifact) matches? -> 409 if not
     |                                         |-- execute SAFE_HANDLERS
     |<- {status, result, verification} ------|
     |                                        |
     |-- GET /manifest / GET /audit-log ------>|
     |<- current manifest / full audit log ---|
```

---

## Key Code Pattern

```python
# supply_chain.py — gate 1: a manifest entry is only real if it's signed
# by an approved publisher's actual private key
def publish(self, tool_name, publisher_id, artifact, signature_hex):
    public_key = APPROVED_PUBLISHERS.get(publisher_id)
    if public_key is None:
        return False, "unapproved_publisher", "..."
    artifact_hash = sha256_hex(artifact)
    try:
        public_key.verify(bytes.fromhex(signature_hex), artifact_hash.encode())
    except (InvalidSignature, ValueError):
        return False, "invalid_signature", "..."
    self._manifest[tool_name] = ManifestEntry(tool_name, publisher_id, artifact_hash)
    return True, "ok", "..."
```

```python
# supply_chain.py — gate 2: loading only succeeds if the artifact about
# to execute is byte-for-byte what the manifest approved
def verify_and_load(self, tool_name, artifact):
    entry = self._manifest.get(tool_name)
    if entry is None:
        return False, "unknown_tool", "..."
    if sha256_hex(artifact) != entry.expected_hash:
        return False, "hash_mismatch", "..."
    return True, "ok", "..."
```

---

## Relationship to MCP09 and MCP10

MCP04, MCP09, and MCP10 are independent layers, like every other pair
of patterns in this repo:

- A tool that passes supply chain verification (MCP04) can still be
  over-provisioned for the caller reaching it — MCP09's role allowlist
  still has to restrict who may call it at all.
- A verified tool's *output* still has to stay inside the caller's
  own tenant boundary — MCP10 still has to scope where that output can
  be read back from.
- Neither MCP09's allowlist nor MCP10's session scoping would have
  caught the attack in this pattern: both assume the tool itself is
  trustworthy once it's reachable. MCP04 is what earns that assumption.

---

## Files

- `supply_chain.py` — tool manifest, approved publishers, hash/signature verification, audit log
- `server.py` — MCP server enforcing manifest publish + load verification
- `client.py` — agent loading a verified tool, then attempting both attacks against the live server
- `attack_demo.py` — no-verification backdoored-tool exfiltration vs. manifest-blocked attempts
- `test_mcp04.py` — verifies verified/tampered/unknown/forged-signature/audit-log cases
- `reset_verification.py` — clears the audit log and reverts the manifest to baseline for a fresh demo run

---

**An MCP server's tool surface is not automatically trustworthy just
because a name resolves to a response that looks right. Without a
signed manifest and a hash check at load time, "the tool ran" and
"the tool was the one that was actually approved" collapse into the
same assumption — which means neither one is actually being verified.**
