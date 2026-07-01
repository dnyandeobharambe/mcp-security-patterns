"""
MCP10 — Context Scoping Pattern
----------------------------------
Every agent session's context is scoped by session_id AND the tenant_id
that created it. A session_id alone never authorizes a read or write —
the caller must present a matching X-Tenant-Id header too. A session_id
from acme-telecom's conversation is worthless in globex-corp's hands,
and an expired session is purged rather than left reachable forever.

OWASP MCP Risk: MCP10:2025 - Cross-Session/Cross-Tenant Context Leakage
"""

from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import uvicorn

from context_scope import ContextStore, DEFAULT_TTL_SECONDS

app = FastAPI(title="Secure MCP Server — MCP10 Context Scoping")

store = ContextStore()


class CreateSessionRequest(BaseModel):
    tenant_id: str
    ttl_seconds: int = DEFAULT_TTL_SECONDS


class WriteContextRequest(BaseModel):
    data: Dict[str, Any]


MOCK_DEVICE_DATA = {
    "acme-telecom": [
        {"device_id": "D-1042", "compliance": "NON_COMPLIANT", "owner": "acme-telecom"},
        {"device_id": "D-1043", "compliance": "COMPLIANT", "owner": "acme-telecom"},
    ],
    "globex-corp": [
        {"device_id": "G-9001", "compliance": "COMPLIANT", "owner": "globex-corp"},
    ],
}


def mock_fetch_devices(tenant_id: str) -> Dict[str, Any]:
    return {"tenant_id": tenant_id, "devices": MOCK_DEVICE_DATA.get(tenant_id, [])}


def _authorize(session_id: str, tenant_id: Optional[str]) -> None:
    """
    KEY SECURITY PATTERN:
    Deterministic two-step lookup, same shape as MCP09's registry check
    — a session that's unknown or expired is rejected before any tenant
    comparison runs, then the presented tenant_id must match the
    session's owner exactly. No implicit trust in "knows the session_id."
    """
    status = store.session_status(session_id)
    if status == "not_found":
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")
    if status == "expired":
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' has expired")

    owner_tenant = store.get_tenant(session_id)
    if not tenant_id or tenant_id != owner_tenant:
        print(
            f"[ContextStore] BLOCKED — session '{session_id}' belongs to tenant "
            f"'{owner_tenant}', request presented tenant '{tenant_id}'"
        )
        raise HTTPException(status_code=403, detail="tenant_id does not match session owner")


@app.post("/sessions")
async def create_session(request: CreateSessionRequest):
    session_id = store.create_session(request.tenant_id, request.ttl_seconds)
    print(f"[ContextStore] Created session '{session_id}' for tenant '{request.tenant_id}'")
    return {"session_id": session_id, "tenant_id": request.tenant_id}


@app.post("/context/{session_id}/write")
async def write_context(
    session_id: str, request: WriteContextRequest, x_tenant_id: str = Header(default=None)
):
    _authorize(session_id, x_tenant_id)
    store.write_context(session_id, request.data)
    print(f"[ContextStore] ALLOWED — tenant '{x_tenant_id}' wrote to session '{session_id}'")
    return {"status": "written", "session_id": session_id}


@app.get("/context/{session_id}")
async def read_context(session_id: str, x_tenant_id: str = Header(default=None)):
    _authorize(session_id, x_tenant_id)
    data = store.read_context(session_id)
    print(f"[ContextStore] ALLOWED — tenant '{x_tenant_id}' read session '{session_id}'")
    return {"session_id": session_id, "tenant_id": x_tenant_id, "context": data}


@app.post("/devices/fetch/{session_id}")
async def fetch_devices(session_id: str, x_tenant_id: str = Header(default=None)):
    """Demo helper: fetch this tenant's device data and store it in the session's own context."""
    _authorize(session_id, x_tenant_id)
    result = mock_fetch_devices(x_tenant_id)
    store.write_context(session_id, {"devices": result["devices"]})
    return {"status": "fetched", "session_id": session_id, "result": result}


@app.delete("/reset")
async def reset():
    """Clear all session context — ready for a fresh demo run."""
    cleared = store.reset()
    print(f"[ContextStore] Reset — cleared {cleared} session(s)")
    return {"cleared": cleared, "message": "Ready for new demo"}


@app.get("/health")
async def health():
    return {"status": "healthy", "pattern": "MCP10-context-scoping"}


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("MCP10 — Context Scoping Pattern")
    print("OWASP MCP Risk: MCP10:2025 - Cross-Session/Cross-Tenant Context Leakage")
    print("=" * 60)
    print("Every session scoped by session_id + tenant_id. Send X-Tenant-Id header.")
    print("=" * 60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8010)
