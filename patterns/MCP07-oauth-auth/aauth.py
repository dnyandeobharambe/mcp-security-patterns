"""
MCP07 — AAuth Protocol Core
------------------------------
Cryptographic agent identity and request signing.
No bearer tokens. No shared secrets. Every request proves possession
of a private key — modeled on HTTP Message Signatures (RFC 9421) and
the AAuth protocol (github.com/christian-posta/aauth-full-demo).

OWASP MCP Risk: MCP07:2025 - Insecure Credential & Identity Management
"""

import base64
import hashlib
import os
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


MAX_CLOCK_SKEW_SECONDS = 120  # how stale/future-dated a signed request may be


@dataclass
class AgentIdentity:
    """An agent's cryptographic identity. The private key never leaves this object."""
    agent_id: str
    _private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls, agent_id: str) -> "AgentIdentity":
        return cls(agent_id=agent_id, _private_key=Ed25519PrivateKey.generate())

    @property
    def public_key_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    @property
    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)


class AauthRegistry:
    """
    Server-side registry mapping agent_id -> public key.

    Stands in for AAuth's JWKS discovery (/.well-known/aauth-agent + jwks_uri):
    in production the server fetches and caches an agent's public key from a
    discoverable endpoint. Here registration is direct, for demo simplicity —
    the security property that matters (verification needs only the public
    key, never the private key) is identical either way.
    """

    def __init__(self):
        self._keys: Dict[str, bytes] = {}

    def register(self, agent_id: str, public_key_bytes: bytes) -> None:
        self._keys[agent_id] = public_key_bytes

    def get_public_key(self, agent_id: str) -> Optional[Ed25519PublicKey]:
        raw = self._keys.get(agent_id)
        if raw is None:
            return None
        return Ed25519PublicKey.from_public_bytes(raw)

    def reset(self) -> int:
        count = len(self._keys)
        self._keys.clear()
        return count


class NonceCache:
    """
    Tracks (agent_id, nonce) pairs already seen. A captured-and-replayed
    request reuses the same nonce — this is what makes replay detectable
    even though the attacker holds a full, validly-signed request.
    """

    def __init__(self):
        self._seen: set = set()

    def seen_before(self, agent_id: str, nonce: str) -> bool:
        return (agent_id, nonce) in self._seen

    def record(self, agent_id: str, nonce: str) -> None:
        self._seen.add((agent_id, nonce))

    def reset(self) -> int:
        count = len(self._seen)
        self._seen.clear()
        return count


def _body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _canonical_string(method: str, path: str, agent_id: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    """
    The "signature base" — what actually gets signed.
    Mirrors RFC 9421 HTTP Message Signatures: derived request components
    (@method, @path) plus a content digest, bound to agent identity and a
    single-use nonce.
    """
    lines = [
        f"method: {method.upper()}",
        f"path: {path}",
        f"agent-id: {agent_id}",
        f"timestamp: {timestamp}",
        f"nonce: {nonce}",
        f"body-digest: sha256={_body_digest(body)}",
    ]
    return "\n".join(lines).encode("utf-8")


def sign_request(
    identity: AgentIdentity,
    method: str,
    path: str,
    body: bytes,
    timestamp: Optional[str] = None,
    nonce: Optional[str] = None,
) -> Dict[str, str]:
    """
    Client-side: build AAuth headers for an outgoing request.
    Returns headers only — no Authorization header, no bearer token.

    timestamp/nonce can be forced by callers (tests, attack demos) that
    need to construct a specific signed-but-invalid request; normal callers
    leave both as None and get fresh values.
    """
    timestamp = timestamp or str(int(time.time()))
    nonce = nonce or os.urandom(16).hex()
    canonical = _canonical_string(method, path, identity.agent_id, timestamp, nonce, body)
    signature = identity.sign(canonical)

    return {
        "X-Aauth-Agent-Id": identity.agent_id,
        "X-Aauth-Timestamp": timestamp,
        "X-Aauth-Nonce": nonce,
        "X-Aauth-Signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_request(
    registry: AauthRegistry,
    nonces: NonceCache,
    method: str,
    path: str,
    headers: Dict[str, str],
    body: bytes,
) -> Tuple[bool, Optional[str], str]:
    """
    Server-side: verify a signed request.
    Returns (ok, agent_id, reason). On failure agent_id is None and reason
    explains exactly which check failed.
    """
    agent_id = headers.get("X-Aauth-Agent-Id")
    timestamp = headers.get("X-Aauth-Timestamp")
    nonce = headers.get("X-Aauth-Nonce")
    signature_b64 = headers.get("X-Aauth-Signature")

    if not all([agent_id, timestamp, nonce, signature_b64]):
        return False, None, "missing AAuth headers"

    public_key = registry.get_public_key(agent_id)
    if public_key is None:
        return False, None, f"unknown agent identity: {agent_id}"

    try:
        ts = int(timestamp)
    except ValueError:
        return False, None, "malformed timestamp"

    if abs(time.time() - ts) > MAX_CLOCK_SKEW_SECONDS:
        return False, None, "timestamp outside allowed window — stale or replayed request"

    if nonces.seen_before(agent_id, nonce):
        return False, None, "nonce already used — replay detected"

    canonical = _canonical_string(method, path, agent_id, timestamp, nonce, body)

    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, canonical)
    except (InvalidSignature, ValueError):
        return False, None, "signature verification failed — request was tampered with or forged"

    # Record the nonce only after the signature checks out, so an attacker
    # probing with garbage signatures can't burn nonces and deny service
    # to the real agent.
    nonces.record(agent_id, nonce)

    return True, agent_id, "ok"
