"""
Always-On Security — Secure Messenger
Handles HMAC-SHA256 signing of all outgoing telemetry messages.
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
_FALLBACK_ID_FILE = "/tmp/node_uuid"


def _load_hmac_secret() -> bytes:
    """Resolve HMAC secret: env → file → ephemeral fallback."""
    env_val = os.environ.get(_SECRET_ENV_VAR, "").strip()
    if env_val:
        return env_val.encode()

    if Path(_SECRET_FILE).exists():
        try:
            secret = Path(_SECRET_FILE).read_text().strip()
            if secret:
                return secret.encode()
        except OSError as e:
            log.error(f"Failed to read secret file: {e}")

    ephemeral = secrets.token_hex(32)
    log.critical(
        "HMAC_SECRET not configured! Using ephemeral secret."
    )
    return ephemeral.encode()


def _load_machine_id() -> str:
    """Return a stable hardware/container identity."""
    try:
        mid = Path(_MACHINE_ID_FILE).read_text().strip()
        if mid:
            return mid
    except OSError:
        pass

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
    return uid


class SecureMessenger:
    def __init__(self, node_name: str, secret_bytes: bytes = None, machine_id: str = None):
        self._node = node_name
        self._secret = secret_bytes or _load_hmac_secret()
        self._machine_id = machine_id or _load_machine_id()
        self._seq = 0
        self._lock = threading.Lock()

    def _next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    @staticmethod
    def _canonical_body(payload: dict) -> bytes:
        return json.dumps(
            {k: v for k, v in payload.items() if k != "hmac"},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode()

    def sign(self, payload: dict) -> dict:
        seq = self._next_seq()
        now = datetime.now(timezone.utc).isoformat()

        envelope = dict(payload)
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


def verify_message(msg: dict, secret: bytes) -> bool:
    received_digest = msg.get("hmac", "")
    if not received_digest:
        return False

    body_bytes = SecureMessenger._canonical_body(msg)
    expected = _hmac.new(secret, body_bytes, hashlib.sha256).hexdigest()
    return _hmac.compare_digest(received_digest, expected)
