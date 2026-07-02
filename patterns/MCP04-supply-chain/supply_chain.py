"""
MCP04 — Supply Chain Verification Core
------------------------------------------
A tool is not trustworthy just because its name is recognized. Two
deterministic gates, checked at two different times, decide whether a
tool's artifact is ever allowed to execute:

  publish()         — registering (or replacing) a manifest entry
                       requires a signature that verifies against an
                       APPROVED publisher's public key. This is where a
                       forged or self-signed manifest entry is rejected,
                       before it ever becomes something loadable.
  verify_and_load()  — actually loading a tool's artifact to execute it
                       requires the artifact's hash to match the hash
                       the manifest recorded at publish time. This is
                       where a swapped-in or tampered artifact is
                       rejected, even under a tool_name that is
                       legitimately in the manifest.

Neither gate trusts anything the request itself claims about identity —
publisher public keys are held server-side in APPROVED_PUBLISHERS, never
supplied by the caller trying to load or publish a tool.

OWASP MCP Risk: MCP04:2025 - Supply Chain Vulnerabilities (via MCP)
"""

import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Publisher:
    """A tool publisher's signing identity. The private key never leaves this object."""
    publisher_id: str
    _private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls, publisher_id: str) -> "Publisher":
        return cls(publisher_id=publisher_id, _private_key=Ed25519PrivateKey.generate())

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def sign_hash(self, artifact_hash: str) -> str:
        return self._private_key.sign(artifact_hash.encode("utf-8")).hex()


@dataclass
class ManifestEntry:
    tool_name: str
    publisher_id: str
    expected_hash: str  # sha256 hex of the approved artifact bytes


@dataclass
class LoadRecord:
    operation: str  # "publish" | "load"
    tool_name: str
    publisher_id: Optional[str]
    verified: bool
    code: str
    reason: str
    ts: float = field(default_factory=time.time)


# Demo publisher identities. In production these public keys would be
# distributed out-of-band (a hardware key, a signed release pipeline) —
# never supplied by the same request that's trying to load a tool.
_acme_security = Publisher.generate("acme-security")
_iotsec_labs = Publisher.generate("iotsec-labs")
ROGUE_VENDOR = Publisher.generate("rogue-vendor")  # a real keypair; simply never approved

APPROVED_PUBLISHERS: Dict[str, Ed25519PublicKey] = {
    "acme-security": _acme_security.public_key,
    "iotsec-labs": _iotsec_labs.public_key,
}

# The exact artifact bytes each publisher shipped for the approved
# release of each tool. Hashing happens once, at publish time — this is
# the trusted baseline every later load attempt is checked against.
COMPLIANCE_CHECKER_ARTIFACT = (
    b"def compliance_checker(device_id):\n"
    b"    return lookup_compliance_status(device_id)\n"
)
FIRMWARE_VALIDATOR_ARTIFACT = (
    b"def firmware_validator(device_id, target_version):\n"
    b"    return validate_firmware(device_id, target_version)\n"
)

_BASELINE_MANIFEST: Dict[str, ManifestEntry] = {
    "compliance_checker": ManifestEntry(
        "compliance_checker", "acme-security", sha256_hex(COMPLIANCE_CHECKER_ARTIFACT)
    ),
    "firmware_validator": ManifestEntry(
        "firmware_validator", "iotsec-labs", sha256_hex(FIRMWARE_VALIDATOR_ARTIFACT)
    ),
}

# Signatures the baseline publishers produced over their own approved
# hashes. Demo callers (client.py, attack_demo.py, tests) that need a
# genuinely valid signature — e.g. to publish a legitimate new version —
# can reuse these rather than re-deriving publisher private keys, which
# never leave this module.
BASELINE_SIGNATURES: Dict[str, str] = {
    "compliance_checker": _acme_security.sign_hash(_BASELINE_MANIFEST["compliance_checker"].expected_hash),
    "firmware_validator": _iotsec_labs.sign_hash(_BASELINE_MANIFEST["firmware_validator"].expected_hash),
}


class SupplyChainVerifier:
    """
    Server-side manifest + audit log. Every publish and every load goes
    through this class — the deterministic Python layer, not the LLM —
    so a tool either clears an explicit signature check (to enter the
    manifest) and an explicit hash check (to execute), or it's rejected.
    """

    def __init__(self):
        self._manifest: Dict[str, ManifestEntry] = dict(_BASELINE_MANIFEST)
        self._log: List[LoadRecord] = []

    def publish(
        self, tool_name: str, publisher_id: str, artifact: bytes, signature_hex: str
    ) -> Tuple[bool, str, str]:
        public_key = APPROVED_PUBLISHERS.get(publisher_id)
        if public_key is None:
            return self._record(
                "publish", tool_name, publisher_id, False, "unapproved_publisher",
                f"publisher '{publisher_id}' is not on the approved list",
            )

        artifact_hash = sha256_hex(artifact)
        try:
            signature = bytes.fromhex(signature_hex)
            public_key.verify(signature, artifact_hash.encode("utf-8"))
        except (InvalidSignature, ValueError):
            return self._record(
                "publish", tool_name, publisher_id, False, "invalid_signature",
                f"signature does not verify against publisher '{publisher_id}''s key — "
                f"manifest entry forged or corrupted",
            )

        self._manifest[tool_name] = ManifestEntry(tool_name, publisher_id, artifact_hash)
        return self._record(
            "publish", tool_name, publisher_id, True, "ok",
            "signature verified — manifest entry published",
        )

    def verify_and_load(self, tool_name: str, artifact: bytes) -> Tuple[bool, str, str]:
        entry = self._manifest.get(tool_name)
        if entry is None:
            return self._record(
                "load", tool_name, None, False, "unknown_tool",
                f"'{tool_name}' is not in the tool manifest",
            )

        actual_hash = sha256_hex(artifact)
        if actual_hash != entry.expected_hash:
            return self._record(
                "load", tool_name, entry.publisher_id, False, "hash_mismatch",
                f"artifact hash {actual_hash[:12]}... does not match manifest hash "
                f"{entry.expected_hash[:12]}... — artifact tampered since publish",
            )

        return self._record(
            "load", tool_name, entry.publisher_id, True, "ok",
            "hash verified against manifest",
        )

    def get_manifest(self) -> Dict[str, ManifestEntry]:
        return dict(self._manifest)

    def _record(self, operation, tool_name, publisher_id, verified, code, reason):
        self._log.append(LoadRecord(operation, tool_name, publisher_id, verified, code, reason))
        return verified, code, reason

    def get_log(self) -> List[LoadRecord]:
        return list(self._log)

    def reset(self) -> int:
        count = len(self._log)
        self._log.clear()
        self._manifest = dict(_BASELINE_MANIFEST)
        return count
