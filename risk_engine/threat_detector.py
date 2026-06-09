"""
Always-On Security — Threat Detector
Central threat detection: rogue node, impersonation, flood, lateral movement,
config tamper, unauthorized process, silent node.
"""
import logging
import os
import time
from collections import defaultdict, deque

import yaml

from alert_manager import ThreatSignal

log = logging.getLogger("threat_detector")
_ALLOWLIST_PATH = os.getenv("ALLOWLIST_PATH", "/opt/security/config/allowlist.yaml")


def _load_config() -> dict:
    try:
        with open(_ALLOWLIST_PATH) as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        log.warning(f"Could not load allowlist config: {e}")
        return {}


class ThreatDetector:
    def __init__(self, store):
        self._store = store
        cfg = _load_config()
        self._allowed_nodes = set(cfg.get("allowed_nodes", []))
        flood_cfg = cfg.get("flood_threshold", {})
        self._flood_max = int(flood_cfg.get("max_msgs_per_60s", 20))
        hb_cfg = cfg.get("heartbeat_timeout_seconds", {})
        self._hb_default  = int(hb_cfg.get("default", 30))
        self._hb_per_node = {k: int(v) for k, v in hb_cfg.items() if k != "default"}
        self._flood_times: dict = defaultdict(deque)

    def run(self, event: dict) -> list:
        if event.get("security_alert"):
            return []
        node    = event.get("node", "unknown")
        signals = []
        signals += self._detect_rogue_node(node, event)
        signals += self._detect_impersonation(node, event)
        signals += self._detect_secondary_flood(node, event)
        signals += self._detect_lateral_movement(node, event)
        signals += self._detect_config_tamper(node, event)
        signals += self._detect_unauth_process(node, event)
        return signals

    def _detect_rogue_node(self, node, event) -> list:
        if not self._allowed_nodes or node in self._allowed_nodes:
            return []
        return [ThreatSignal(node_id=node, threat_type="ROGUE_NODE", severity="CRITICAL",
            description=f"Node '{node}' is not in the approved allowlist.",
            evidence={"node": node, "machine_id": event.get("machine_id",""), "allowed": list(self._allowed_nodes)})]

    def _detect_impersonation(self, node, event) -> list:
        claimed_mid = event.get("machine_id", "")
        if not claimed_mid:
            return []
        known = self._store.get_node_identity(node)
        if known is None:
            self._store.upsert_node_identity(node=node, machine_id=claimed_mid, trust_status="TRUSTED")
            return []
        known_mid = known.get("machine_id", "")
        if known_mid and known_mid != claimed_mid:
            self._store.upsert_node_identity(node=node, machine_id=claimed_mid, trust_status="SUSPECT")
            return [ThreatSignal(node_id=node, threat_type="NODE_IMPERSONATION", severity="CRITICAL",
                description=f"Node {node} changed its machine_id.",
                evidence={"node": node, "known_machine_id": known_mid, "claimed_machine_id": claimed_mid})]
        self._store.upsert_node_identity(node=node, machine_id=claimed_mid, trust_status=known.get("trust_status","TRUSTED"))
        return []

    def _detect_secondary_flood(self, node, event) -> list:
        now, cutoff = time.time(), time.time() - 60
        dq = self._flood_times[node]
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)
        threshold = self._flood_max * 2
        if len(dq) > threshold:
            return [ThreatSignal(node_id=node, threat_type="FLOOD_ATTACK", severity="MEDIUM",
                description=f"Engine: flood from {node}: {len(dq)} msgs/60s",
                evidence={"node": node, "count": len(dq), "threshold": threshold})]
        return []

    def _detect_lateral_movement(self, node, event) -> list:
        ssh_count = int(event.get("ssh_connections", 0))
        if ssh_count <= 0:
            return []
        peers = event.get("lateral_peers", [])
        return [ThreatSignal(node_id=node, threat_type="LATERAL_MOVEMENT", severity="HIGH",
            description=f"Node {node} has {ssh_count} unexpected SSH connections to {len(peers)} peer(s).",
            evidence={"node": node, "ssh_count": ssh_count, "lateral_peers": peers})]

    def _detect_config_tamper(self, node, event) -> list:
        tampered = event.get("tampered_files", [])
        if not tampered or not event.get("config_tamper"):
            return []
        return [ThreatSignal(node_id=node, threat_type="CONFIG_TAMPER", severity="HIGH",
            description=f"Node {node}: {len(tampered)} config file(s) modified.",
            evidence={"node": node, "tampered_files": tampered})]

    def _detect_unauth_process(self, node, event) -> list:
        procs = event.get("unauthorized_procs", [])
        if not procs:
            return []
        names = [p.get("name","?") for p in procs]
        return [ThreatSignal(node_id=node, threat_type="UNAUTH_PROCESS", severity="MEDIUM",
            description=f"Node {node}: {len(procs)} unauthorized process(es): {names}",
            evidence={"node": node, "processes": procs})]

    def build_silent_node_signal(self, node: str, delta_seconds: float) -> ThreatSignal:
        hb_timeout = self._hb_per_node.get(node, self._hb_default)
        return ThreatSignal(node_id=node, threat_type="SILENT_NODE", severity="HIGH",
            description=f"Node {node} has not reported for {delta_seconds:.0f}s (timeout={hb_timeout}s).",
            evidence={"node": node, "silent_seconds": round(delta_seconds,1), "configured_timeout": hb_timeout})
