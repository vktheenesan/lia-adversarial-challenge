"""
LIA Immune Memory — Cryptographically Signed Structured Incident Memory (Ed25519)
"""

import json
import hashlib
import hmac
from typing import List, Dict, Any, Optional

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    HAS_ED25519 = True
except ImportError:
    HAS_ED25519 = False

try:
    from core.event_bus import EventBus, NormalizedEvent
except ImportError:
    try:
        from engine.core.event_bus import EventBus, NormalizedEvent
    except ImportError:
        from core.event_bus.bus import EventBus, NormalizedEvent


class FallbackHmacKey:
    """Provides HMAC-SHA512 verification fallback if cryptography library is unavailable."""
    def __init__(self, secret: bytes):
        self.secret = secret

    def verify(self, sig_bytes: bytes, payload_bytes: bytes):
        computed = hmac.new(self.secret, payload_bytes, hashlib.sha512).digest()
        if not hmac.compare_digest(sig_bytes, computed):
            raise ValueError("HMAC signature verification failed")

class ImmuneMemoryStore:
    """
    Structured, tamper-evident incident memory utilizing Ed25519 asymmetric signatures
    and append-only Merkle-chained hash links.
    """

    def __init__(self, event_bus: EventBus, private_key: Any = None):
        self.event_bus = event_bus
        self.records: List[Dict[str, Any]] = []
        self.last_record_hash: str = "0" * 64
        
        # Ed25519 Private Key Generation with robust fallback
        if HAS_ED25519:
            if private_key is None:
                self.private_key = ed25519.Ed25519PrivateKey.generate()
            else:
                self.private_key = private_key
            self.public_key = self.private_key.public_key()
        else:
            self.private_key = b"librae_fallback_hmac_secret_2026_bound"
            self.public_key = FallbackHmacKey(self.private_key)

        self.event_bus.subscribe_all(self._record_event)

    @classmethod
    def compute_canonical_payload(
        cls,
        event_id: str,
        event_type: str,
        timestamp: float,
        source: str,
        component: str,
        severity: str,
        metadata: Any,
        prev_hash: str
    ) -> str:
        """Constructs an unambiguous, canonical serialized payload representation."""
        meta_json = json.dumps(metadata, sort_keys=True, separators=(',', ':'))
        return f"{event_id}|{event_type}|{timestamp:.6f}|{source}|{component}|{severity}|{prev_hash}|{meta_json}"

    def record_trajectory_step(self, event: NormalizedEvent) -> Dict[str, Any]:
        """
        Explicitly records a security or trajectory step with provenance validation,
        hash chaining (prev_hash), and Ed25519 cryptographic signature.
        Rejects forged origins not in authenticated component list.
        """
        valid_sources = ["shield", "vision", "reflex", "heal", "kernel", "hypervisor", "audit", "challenge_runner"]
        if event.source not in valid_sources:
            self.event_bus.publish(NormalizedEvent(
                event_type="UNAUTHORIZED_MEMORY_MUTATION",
                source="memory_engine",
                component="dag_validator",
                severity="CRITICAL",
                metadata={"attempted_source": event.source}
            ))
            raise PermissionError(f"Immune memory rejected unauthenticated event source: {event.source}")

        prev_hash = self.last_record_hash
        payload = self.compute_canonical_payload(
            event.event_id,
            event.event_type,
            event.timestamp,
            event.source,
            event.component,
            event.severity,
            event.metadata,
            prev_hash
        )
        payload_bytes = payload.encode("utf-8")
        sha256_hash = hashlib.sha256(payload_bytes).hexdigest()

        if HAS_ED25519 and hasattr(self.private_key, "sign"):
            ed25519_sig = self.private_key.sign(payload_bytes).hex()
        else:
            ed25519_sig = hmac.new(self.private_key, payload_bytes, hashlib.sha512).digest().hex()

        record = {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "timestamp": event.timestamp,
            "source": event.source,
            "component": event.component,
            "severity": event.severity,
            "metadata": event.metadata,
            "prev_hash": prev_hash,
            "sha256_hash": sha256_hash,
            "ed25519_signature": ed25519_sig,
            "payload_str": payload
        }
        self.last_record_hash = sha256_hash
        self.records.append(record)
        return record

    def _record_event(self, event: NormalizedEvent):
        # Break recursion on self-generated memory audit events
        if event.source == "memory_engine" or event.event_type == "UNAUTHORIZED_MEMORY_MUTATION":
            return
        # Record security-relevant events
        if event.severity in ("WARNING", "HIGH", "CRITICAL") or "POLICY" in event.event_type or "HEAL" in event.event_type:
            try:
                self.record_trajectory_step(event)
            except PermissionError:
                pass

    def verify_record(self, record: Dict[str, Any]) -> bool:
        """
        Cryptographically verifies the record using the daemon's public key.
        Reconstructs canonical payload from record fields to detect any tampering
        with event_id, source, component, metadata, timestamp, or prev_hash.
        """
        try:
            # Reconstruct the canonical payload from individual fields
            reconstructed_payload = self.compute_canonical_payload(
                record.get("event_id", ""),
                record.get("event_type", ""),
                float(record.get("timestamp", 0.0)),
                record.get("source", ""),
                record.get("component", ""),
                record.get("severity", ""),
                record.get("metadata", {}),
                record.get("prev_hash", "0" * 64)
            )
            payload_bytes = reconstructed_payload.encode("utf-8")

            # Verify hash
            computed_hash = hashlib.sha256(payload_bytes).hexdigest()
            if computed_hash != record.get("sha256_hash"):
                return False

            # Verify Ed25519 or HMAC signature
            sig_bytes = bytes.fromhex(record.get("ed25519_signature", ""))
            self.public_key.verify(sig_bytes, payload_bytes)
            return True
        except Exception:
            return False


    def get_records(self) -> List[Dict[str, Any]]:
        return list(self.records)
