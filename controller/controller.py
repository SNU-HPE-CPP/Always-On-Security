"""
Always-On Security — Controller (Enhanced Security Layer)
6-tier security gate: HMAC verify, rogue node, replay guard,
flood guard, impersonation check, duplicate node ID.
"""
import json
import logging
import os
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone

import yaml
import zmq

from secure_messenger import _load_hmac_secret, verify_message

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("controller")

OFFSET_PATH    = "/data/controller.offset"
ALLOWLIST_PATH = os.getenv("ALLOWLIST_PATH", "/opt/security/config/allowlist.yaml")


def _load_allowlist_config() -> dict:
    try:
        with open(ALLOWLIST_PATH) as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        log.error(f"Could not load allowlist config: {e}")
        return {}


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


class ReplayGuard:
    def __init__(self, max_age_seconds: int = 30, window_size: int = 1000):
        self.max_age = max_age_seconds
        self.window  = window_size
        self._seen: dict   = defaultdict(deque)
        self._last_seq: dict = {}

    def check(self, node, msg_id, seq, msg_ts_str):
        now = time.time()
        try:
            msg_ts = datetime.fromisoformat(msg_ts_str.replace("Z", "+00:00")).timestamp()
            age = abs(now - msg_ts)
            if age > self.max_age:
                return True, f"Stale timestamp: {age:.1f}s old"
        except Exception:
            return True, "Invalid or missing timestamp"
        last = self._last_seq.get(node, -1)
        if seq <= last:
            return True, f"Non-monotonic seq {seq} (last {last})"
        dq = self._seen[node]
        cutoff = now - self.max_age
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        if msg_id in {e[1] for e in dq}:
            return True, f"Duplicate msg_id {msg_id}"
        if len(dq) >= self.window:
            dq.popleft()
        dq.append((now, msg_id, seq))
        self._last_seq[node] = seq
        return False, ""


class FloodGuard:
    def __init__(self, max_per_window: int = 20, window_seconds: int = 60):
        self.max_per_window = max_per_window
        self.window = window_seconds
        self._times: dict = defaultdict(deque)

    def check(self, node):
        now = time.time()
        dq  = self._times[node]
        while dq and dq[0] < now - self.window:
            dq.popleft()
        dq.append(now)
        return len(dq) > self.max_per_window, len(dq)


def _make_security_alert(node, threat_type, severity, description, evidence,
                          recommended_action, offset) -> dict:
    return {
        "node": node, "event_type": "SECURITY_ALERT",
        "reasons": [description], "cpu_usage": 0.0, "memory_usage": 0.0,
        "process_count": 0, "is_busy": False, "active_job_type": None,
        "_offset": offset, "_received_at": datetime.now(timezone.utc).isoformat(),
        "security_alert": True, "alert_id": str(uuid.uuid4()),
        "threat_type": threat_type, "severity": severity,
        "description": description, "evidence": evidence,
        "recommended_action": recommended_action,
    }


def main():
    cfg        = _load_allowlist_config()
    allowed    = set(cfg.get("allowed_nodes", []))
    flood_cfg  = cfg.get("flood_threshold", {})
    replay_cfg = cfg.get("replay_protection", {})

    hmac_secret  = _load_hmac_secret()
    replay_guard = ReplayGuard(
        max_age_seconds=int(replay_cfg.get("max_age_seconds", 30)),
        window_size=int(replay_cfg.get("window_seq_track", 1000)),
    )
    flood_guard = FloodGuard(max_per_window=int(flood_cfg.get("max_msgs_per_60s", 20)))

    node_machine_ids: dict = {}
    offset = load_offset()

    log.info(f"Controller starting at offset {offset}")
    log.info(f"Allowed nodes: {allowed or '(all)'}")

    ctx  = zmq.Context()
    recv = ctx.socket(zmq.PULL)
    recv.bind("tcp://*:5555")
    fwd  = ctx.socket(zmq.PUSH)
    fwd.connect("tcp://risk-engine:5556")
    log.info("Listening on :5555 -> risk-engine:5556")

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
        offset    += 1

        # CHECK 1: HMAC
        if not verify_message(raw, hmac_secret):
            log.warning(f"[TAMPER] HMAC invalid | node={node}")
            fwd.send_json(_make_security_alert(node, "TELEMETRY_TAMPER", "HIGH",
                f"HMAC signature invalid from node={node}",
                {"msg_id": msg_id, "node": node},
                "Investigate node for compromise or MITM attack.", offset))
            save_offset(offset)
            continue

        # CHECK 2: Rogue node
        if allowed and node not in allowed:
            log.warning(f"[ROGUE_NODE] Unknown node={node}")
            fwd.send_json(_make_security_alert(node, "ROGUE_NODE", "CRITICAL",
                f"Rogue node detected: '{node}' not in allowlist.",
                {"node": node, "machine_id": machine_id},
                "Block node immediately.", offset))
            save_offset(offset)
            continue

        # CHECK 3: Replay
        is_replay, replay_reason = replay_guard.check(node, msg_id, seq, timestamp)
        if is_replay:
            log.warning(f"[REPLAY] node={node} | {replay_reason}")
            fwd.send_json(_make_security_alert(node, "REPLAY_ATTACK", "HIGH",
                f"Replay attack from node={node}: {replay_reason}",
                {"msg_id": msg_id, "seq": seq, "reason": replay_reason},
                "Reject message. Investigate telemetry capture.", offset))
            save_offset(offset)
            continue

        # CHECK 4: Flood
        is_flooding, msg_count = flood_guard.check(node)
        if is_flooding:
            log.warning(f"[FLOOD] node={node} sent {msg_count} msgs/60s")
            fwd.send_json(_make_security_alert(node, "FLOOD_ATTACK", "MEDIUM",
                f"Message flooding from node={node}: {msg_count} msgs/60s",
                {"node": node, "count": msg_count},
                "Rate-limit or quarantine node.", offset))
            offset += 1
            save_offset(offset)

        # CHECK 5: Impersonation
        known_mid = node_machine_ids.get(node)
        if machine_id:
            if known_mid is None:
                node_machine_ids[node] = machine_id
            elif known_mid != machine_id:
                log.warning(f"[IMPERSONATION] node={node} machine_id changed")
                fwd.send_json(_make_security_alert(node, "NODE_IMPERSONATION", "CRITICAL",
                    f"Node {node} machine_id changed — possible impersonation.",
                    {"node": node, "known": known_mid, "claimed": machine_id},
                    "Quarantine node. Verify hardware identity.", offset))
                node_machine_ids[node] = machine_id
                offset += 1
                save_offset(offset)

        # Forward validated message
        save_offset(offset)
        raw["_offset"]      = offset
        raw["_received_at"] = datetime.now(timezone.utc).isoformat()
        raw.pop("hmac", None)
        fwd.send_json(raw)
        log.info(f"Forwarded offset={offset} node={node} event={raw.get('event_type')} seq={seq}")

    ctx.destroy()


if __name__ == "__main__":
    main()
