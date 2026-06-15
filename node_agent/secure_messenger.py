"""
Always-On Security — Secure Messenger
Handles HMAC-SHA256 signing of all outgoing telemetry messages.

Secret resolution order:
  1. HMAC_SECRET environment variable
  2. /run/secrets/hmac_secret file (Docker secrets mount)
  3. Auto-generated ephemeral secret (logs CRITICAL warning — nodes will
     disagree with controller and all messages will be rejected)

Message envelope schema:
  {
    "msg_id":    str,   # UUID4 — for replay deduplication
    "seq":       int,   # Monotonically increasing per-node counter
    "timestamp": str,   # UTC ISO-8601 — for freshness check
    "node":      str,   # Node name / identifier
    "machine_id":str,   # Stable hardware/container identity
    "hmac":      str,   # HMAC-SHA256 hex digest of the canonical body
    ...payload fields...
  }
"""

import hashlib
import hmac as _hmac
import json
import logging
import os
import secrets
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("secure_messenger")

_SECRET_ENV_VAR = "HMAC_SECRET"
_SECRET_FILE = "/run/secrets/hmac_secret"
_MACHINE_ID_FILE = "/etc/machine-id"
_FALLBACK_ID_FILE = "/tmp/node_uuid"  # nosec B108 — intentional fallback path when /etc/machine-id unavailable


# ──────────────────────────────────────────────
# Secret loading (multi-tier, never hardcoded)
# ──────────────────────────────────────────────

def _load_hmac_secret() -> bytes:
    """Resolve HMAC secret: env → file → ephemeral fallback."""
    # Tier 1: environment variable
    env_val = os.environ.get(_SECRET_ENV_VAR, "").strip()
    if env_val:
        log.info("HMAC secret loaded from environment variable.")
        return env_val.encode()

    # Tier 2: Docker secrets file
    if Path(_SECRET_FILE).exists():
        try:
            secret = Path(_SECRET_FILE).read_text().strip()
            if secret:
                log.info(f"HMAC secret loaded from {_SECRET_FILE}.")
                return secret.encode()
        except OSError as e:
            log.error(f"Failed to read secret file: {e}")

    # Tier 3: ephemeral — this node's signatures will be rejected by the
    # controller unless all services share the same ephemeral secret,
    # which is impossible across independent containers.
    # TODO(security): Replace ephemeral fallback with mandatory secret injection
    #                 via orchestration (Vault, K8s Secret, or pre-shared file).
    ephemeral = secrets.token_hex(32)
    log.critical(
        "HMAC_SECRET not configured! Using ephemeral secret. "
        "This node's messages WILL be rejected by the controller. "
        "Set HMAC_SECRET env var identically on all services."
    )
    return ephemeral.encode()


def _load_machine_id() -> str:
    """Return a stable hardware/container identity."""
    # Try /etc/machine-id (standard on systemd hosts)
    try:
        mid = Path(_MACHINE_ID_FILE).read_text().strip()
        if mid:
            return mid
    except OSError:
        pass

    # Persist a generated UUID so it survives restarts within the same container
    fb = Path(_FALLBACK_ID_FILE)
    if fb.exists():
        try:
            uid = fb.read_text().strip()
            if uid:
                return uid
        except OSError:
            pass

    uid = str(uuid.uuid4())
    try:
        fb.write_text(uid)
    except OSError:
        pass
    log.warning(f"machine-id generated: {uid} (stored in {_FALLBACK_ID_FILE})")
    return uid


# ──────────────────────────────────────────────
# SecureMessenger
# ──────────────────────────────────────────────

class SecureMessenger:
    """
    Thread-safe message signer.
    One instance per agent process — seq counter is global per instance.
    """

    def __init__(self, node_name: str):
        self._node = node_name
        self._secret = _load_hmac_secret()
        self._machine_id = _load_machine_id()
        self._seq = 0
        self._lock = threading.Lock()
        log.info(
            f"SecureMessenger ready | node={self._node} | "
            f"machine_id={self._machine_id[:8]}..."
        )

    def _next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    @staticmethod
    def _canonical_body(payload: dict) -> bytes:
        """
        Produce a deterministic JSON serialisation for signing.
        Sorted keys ensure consistent ordering regardless of dict insertion order.
        The 'hmac' field is excluded (it does not exist yet at signing time).
        """
        return json.dumps(
            {k: v for k, v in payload.items() if k != "hmac"},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode()

    def sign(self, payload: dict) -> dict:
        """
        Add security envelope fields and an HMAC-SHA256 digest to payload.
        Returns a new dict (original is not mutated).
        """
        seq = self._next_seq()
        now = datetime.now(timezone.utc).isoformat()

        envelope = dict(payload)  # shallow copy
        envelope.update({
            "msg_id":     str(uuid.uuid4()),
            "seq":        seq,
            "timestamp":  now,
            "node":       self._node,
            "machine_id": self._machine_id,
        })

        body_bytes = self._canonical_body(envelope)
        digest = _hmac.new(self._secret, body_bytes, hashlib.sha256).hexdigest()
        envelope["hmac"] = digest
        return envelope


# ──────────────────────────────────────────────
# Verification helper (used by controller)
# ──────────────────────────────────────────────

def verify_message(msg: dict, secret: bytes) -> bool:
    """
    Verify the HMAC digest of a received message.
    Returns True if the signature is valid, False otherwise.
    Uses hmac.compare_digest to prevent timing attacks.
    """
    received_digest = msg.get("hmac", "")
    if not received_digest:
        return False

    body_bytes = SecureMessenger._canonical_body(msg)
    expected = _hmac.new(secret, body_bytes, hashlib.sha256).hexdigest()
    return _hmac.compare_digest(received_digest, expected)
