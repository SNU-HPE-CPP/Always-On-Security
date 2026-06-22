"""
Always-On Security — Controller (Enhanced Security Layer)

Acts as the FIRST LINE OF DEFENSE between nodes and the risk engine.
Performs 6 security checks on every incoming message BEFORE forwarding:

  1. HMAC-SHA256 verification      — drops tampered messages
  2. Rogue node detection           — rejects unknown node IDs
  3. Replay attack guard            — rejects stale / reused seq + msg_id
  4. Message flooding detection     — alerts on excessive message rate
  5. Duplicate node ID detection    — flags two sources using same node name
  6. Node impersonation detection   — flags machine_id change for known node

Alerts for these conditions are forwarded as synthetic events to the risk
engine so they appear in the dashboard and alert DB.
"""

import json
import logging
import os
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml
import zmq

from secure_messenger import _load_hmac_secret, verify_message

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("controller")

# ─────────────────────────────────────────
# Paths
# ─────────────────────────────────────────
OFFSET_PATH   = "/data/controller.offset"
BLACKLIST_PATH = "/data/rogue_blacklist.yaml"
ALLOWLIST_PATH = os.getenv("ALLOWLIST_PATH", "/opt/security/config/allowlist.yaml")

# ─────────────────────────────────────────
# Config loading
# ─────────────────────────────────────────

def _load_allowlist_config() -> dict:
    try:
        with open(ALLOWLIST_PATH) as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        log.error(f"Could not load allowlist config: {e}")
        return {}


# ─────────────────────────────────────────
# Offset persistence
# ─────────────────────────────────────────

def load_offset() -> int:
    try:
        with open(OFFSET_PATH) as f:
            return int(f.read().strip())
    except Exception:
        return 0


def save_offset(offset: int) -> None:
    tmp = OFFSET_PATH + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(offset))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, OFFSET_PATH)


def load_blacklist() -> set:
    try:
        with open(BLACKLIST_PATH) as f:
            data = yaml.safe_load(f)
            return set(data) if isinstance(data, list) else set()
    except Exception:
        return set()


def save_blacklist(blacklist: set) -> None:
    tmp = BLACKLIST_PATH + ".tmp"
    with open(tmp, "w") as f:
        yaml.dump(list(blacklist), f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, BLACKLIST_PATH)


# ─────────────────────────────────────────
# Security state (in-memory, controller lifetime)
# ─────────────────────────────────────────

class ReplayGuard:
    """Per-node sliding window of seen (msg_id, seq) pairs."""

    def __init__(self, max_age_seconds: int = 30, window_size: int = 1000):
        self.max_age   = max_age_seconds
        self.window    = window_size
        # node → deque of (seen_at_float, msg_id, seq)
        self._seen: dict[str, deque] = defaultdict(deque)
        # node → last_seq
        self._last_seq: dict[str, int] = {}

    def check(self, node: str, msg_id: str, seq: int, msg_ts_str: str) -> tuple[bool, str]:
        """
        Returns (is_replay: bool, reason: str).
        Evicts old entries before checking.
        """
        now = time.time()

        # 1. Timestamp freshness
        try:
            msg_ts = datetime.fromisoformat(msg_ts_str.replace("Z", "+00:00")).timestamp()
            age = abs(now - msg_ts)
            if age > self.max_age:
                return True, f"Stale timestamp: {age:.1f}s old (max {self.max_age}s)"
        except Exception:
            return True, "Invalid or missing timestamp"

        # 2. Sequence number monotonicity
        last = self._last_seq.get(node, -1)
        if seq <= last:
            return True, f"Non-monotonic seq {seq} (last seen {last})"

        # 3. Duplicate msg_id in sliding window
        dq = self._seen[node]
        cutoff = now - self.max_age
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        seen_ids = {entry[1] for entry in dq}
        if msg_id in seen_ids:
            return True, f"Duplicate msg_id {msg_id}"

        # All checks passed — record
        if len(dq) >= self.window:
            dq.popleft()
        dq.append((now, msg_id, seq))
        self._last_seq[node] = seq
        return False, ""


class FloodGuard:
    """Sliding window message rate limiter per node."""

    def __init__(self, max_per_window: int = 20, window_seconds: int = 60):
        self.max_per_window = max_per_window
        self.window         = window_seconds
        self._times: dict[str, deque] = defaultdict(deque)

    def check(self, node: str) -> tuple[bool, int]:
        """Returns (is_flooding: bool, current_count: int)."""
        now    = time.time()
        cutoff = now - self.window
        dq     = self._times[node]
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)
        count = len(dq)
        return count > self.max_per_window, count


# ─────────────────────────────────────────
# Alert 
# ─────────────────────────────────────────

def _make_security_alert(
    node: str,
    threat_type: str,
    severity: str,
    description: str,
    evidence: dict,
    recommended_action: str,
    offset: int,
) -> dict:
    """Build a synthetic security-alert event for the risk engine."""
    return {
        # Standard telemetry envelope (risk engine expects these)
        "node":         node,
        "event_type":   "SECURITY_ALERT",
        "reasons":      [description],
        "cpu_usage":    0.0,
        "memory_usage": 0.0,
        "process_count": 0,
        "is_busy":      False,
        "active_job_type": None,
        "_offset":      offset,
        "_received_at": datetime.now(timezone.utc).isoformat(),
        # Security-specific fields
        "security_alert": True,
        "alert_id":       str(uuid.uuid4()),
        "threat_type":    threat_type,
        "severity":       severity,
        "description":    description,
        "evidence":       evidence,
        "recommended_action": recommended_action,
    }


# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────

def main():
    cfg         = _load_allowlist_config()
    allowed     = set(cfg.get("allowed_nodes", []))
    flood_cfg   = cfg.get("flood_threshold", {})
    replay_cfg  = cfg.get("replay_protection", {})

    flood_max   = int(flood_cfg.get("max_msgs_per_60s", 20))
    replay_age  = int(replay_cfg.get("max_age_seconds", 30))
    replay_win  = int(replay_cfg.get("window_seq_track", 1000))

    hmac_secret = _load_hmac_secret()

    replay_guard = ReplayGuard(max_age_seconds=replay_age, window_size=replay_win)
    flood_guard  = FloodGuard(max_per_window=flood_max, window_seconds=60)

    # Node identity tracking (name → machine_id, name → source_addr)
    node_machine_ids: dict[str, str]  = {}
    node_source_addrs: dict[str, str] = {}

    rogue_blacklist = load_blacklist()
    flood_alerted: dict[str, float] = {}  # node → timestamp of last FLOOD_ATTACK alert
    offset = load_offset()
    log.info(f"Controller starting at offset {offset}")
    log.info(f"Allowed nodes: {allowed or '(all — no allowlist configured)'}")
    log.info(f"Flood threshold: {flood_max} msgs/60s | Replay max age: {replay_age}s")

    ctx  = zmq.Context()

    # Receive from node agents
    recv = ctx.socket(zmq.PULL)
    recv.bind("tcp://*:5555")

    # Forward to risk engine
    fwd = ctx.socket(zmq.PUSH)
    fwd.connect("tcp://risk-engine:5556")

    # Track source addresses for duplicate-ID / impersonation detection.
    # ZMQ PULL doesn't expose peer addresses natively; we use the machine_id
    # field inside the message as the distinguishing identity.

    log.info("Controller listening on :5555 -> risk-engine:5556")

    while True:
        try:
            raw = recv.recv_json()
        except Exception as e:
            log.error(f"ZMQ recv error: {e}")
            continue

        node       = raw.get("node", "UNKNOWN")
        machine_id = raw.get("machine_id", "")
        msg_id     = raw.get("msg_id", "")
        seq        = raw.get("seq", -1)
        timestamp  = raw.get("timestamp", "")

        # ── PRE-CHECK: Silently drop known rogue nodes ─────────────────
        if node in rogue_blacklist:
            continue

        offset += 1

        # ── CHECK 1: HMAC Verification ─────────────────────────────────
        if not verify_message(raw, hmac_secret):
            log.warning(
                f"[TAMPER_ATTEMPT] HMAC invalid | node={node} "
                f"msg_id={msg_id} | Dropping message."
            )
            alert = _make_security_alert(
                node=node,
                threat_type="TELEMETRY_TAMPER",
                severity="HIGH",
                description=f"HMAC signature invalid from node={node}",
                evidence={"msg_id": msg_id, "node": node},
                recommended_action="Investigate node for compromise or MITM attack.",
                offset=offset,
            )
            save_offset(offset)
            fwd.send_json(alert)
            continue

        # ── CHECK 2: Rogue Node Detection ─────────────────────────────
        if allowed and node not in allowed:
            log.warning(f"[ROGUE_NODE] Unknown node={node} not in allowlist.")
            
            # Add to persistent blacklist so subsequent messages are dropped
            rogue_blacklist.add(node)
            save_blacklist(rogue_blacklist)
            
            alert = _make_security_alert(
                node=node,
                threat_type="ROGUE_NODE",
                severity="CRITICAL",
                description=f"Rogue node detected: '{node}' is not in the allowlist.",
                evidence={"node": node, "machine_id": machine_id, "msg_id": msg_id},
                recommended_action="Block node immediately and investigate its origin.",
                offset=offset,
            )
            save_offset(offset)
            fwd.send_json(alert)
            continue

        # ── CHECK 3: Replay Attack ─────────────────────────────────────
        is_replay, replay_reason = replay_guard.check(node, msg_id, seq, timestamp)
        if is_replay:
            log.warning(f"[REPLAY_ATTACK] node={node} | {replay_reason}")
            alert = _make_security_alert(
                node=node,
                threat_type="REPLAY_ATTACK",
                severity="HIGH",
                description=f"Replay attack detected from node={node}: {replay_reason}",
                evidence={"msg_id": msg_id, "seq": seq, "reason": replay_reason},
                recommended_action="Reject message. Investigate if attacker captured telemetry.",
                offset=offset,
            )
            save_offset(offset)
            fwd.send_json(alert)
            continue

        # ── CHECK 4: Message Flooding ──────────────────────────────────
        is_flooding, msg_count = flood_guard.check(node)
        if is_flooding:
            # Suppress repeated FLOOD_ATTACK alerts for the same node.
            # Emit at most ONE alert per node per 60s window to prevent
            # the alert-generation itself from creating an infinite loop.
            now_ts = time.time()
            last_flood_ts = flood_alerted.get(node, 0.0)
            if now_ts - last_flood_ts >= 60:
                flood_alerted[node] = now_ts
                log.warning(f"[FLOOD_DETECTED] node={node} sent {msg_count} msgs/60s (max={flood_max})")
                alert = _make_security_alert(
                    node=node,
                    threat_type="FLOOD_ATTACK",
                    severity="MEDIUM",
                    description=f"Message flooding from node={node}: {msg_count} msgs in 60s",
                    evidence={"node": node, "count": msg_count, "threshold": flood_max},
                    recommended_action="Rate-limit or quarantine node. Investigate DoS intent.",
                    offset=offset,
                )
                save_offset(offset)
                fwd.send_json(alert)
            # Continue processing original message (don't drop — may be legitimate)

        # ── CHECK 5: Node Impersonation (machine_id change) ────────────
        known_mid = node_machine_ids.get(node)
        if machine_id:
            if known_mid is None:
                node_machine_ids[node] = machine_id
            elif known_mid != machine_id:
                log.warning(
                    f"[IMPERSONATION] node={node} machine_id changed "
                    f"({known_mid[:8]}... -> {machine_id[:8]}...)"
                )
                alert = _make_security_alert(
                    node=node,
                    threat_type="NODE_IMPERSONATION",
                    severity="CRITICAL",
                    description=f"Node {node} machine_id changed — possible impersonation.",
                    evidence={
                        "node": node,
                        "known_machine_id":   known_mid,
                        "claimed_machine_id": machine_id,
                    },
                    recommended_action="Quarantine node. Verify hardware identity out-of-band.",
                    offset=offset,
                )
                # Update to new ID after alerting
                node_machine_ids[node] = machine_id
                offset += 1
                save_offset(offset)
                fwd.send_json(alert)

        # ── CHECK 6: Duplicate Node ID (same name, different machine) ──
        # We detect this by checking if two different machine_ids are
        # both active under the same node name within a short window.
        # (Handled above as part of impersonation detection — same logic.)

        # ── FORWARD VALIDATED MESSAGE ──────────────────────────────────
        save_offset(offset)
        raw["_offset"]      = offset
        raw["_received_at"] = datetime.now(timezone.utc).isoformat()

        # Strip HMAC before forwarding (not needed downstream)
        raw.pop("hmac", None)

        fwd.send_json(raw)
        log.info(
            f"Forwarded offset={offset} node={node} "
            f"event={raw.get('event_type')} seq={seq}"
        )

    ctx.destroy()


if __name__ == "__main__":
    main()
