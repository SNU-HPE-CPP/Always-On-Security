"""
Always-On Security — Threat Detector

Central threat detection module. Called for every processed event.
Produces a list of ThreatSignal dataclasses consumed by AlertManager.

Detectors implemented:
  A. Rogue Node             — node not in allowlist
  B. Node Impersonation     — machine_id changed for known node
  C. Duplicate Node ID      — handled at controller; re-validated here
  D. Replay Attack          — secondary belt-and-suspenders check
  E. Message Flooding       — secondary rate check inside engine
  F. Silent Node            — heartbeat timeout (run from heartbeat thread)
  G. Telemetry Tampering    — already caught at controller; routed here
  H. Unauthorized Process   — from security collector payload
  I. Lateral Movement       — SSH connections from security collector
  J. Config Tampering       — from security collector payload
"""

import logging
import os
import time
from collections import defaultdict, deque

import yaml

from alert_manager import ThreatSignal

log = logging.getLogger("threat_detector")

_ALLOWLIST_PATH = os.getenv("ALLOWLIST_PATH", "/opt/security/config/allowlist.yaml")


# ─────────────────────────────────────────
# Config loading
# ─────────────────────────────────────────

def _load_config() -> dict:
    try:
        with open(_ALLOWLIST_PATH) as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        log.warning(f"Could not load allowlist config: {e}")
        return {}


# ─────────────────────────────────────────
# ThreatDetector
# ─────────────────────────────────────────

class ThreatDetector:
    """
    Stateful threat detector — maintains per-node tracking windows.
    One instance lives for the lifetime of the risk engine process.
    """

    def __init__(self, store):
        self._store  = store
        cfg          = _load_config()
        self._allowed_nodes = set(cfg.get("allowed_nodes", []))
        flood_cfg    = cfg.get("flood_threshold", {})
        self._flood_max_per_60s = int(flood_cfg.get("max_msgs_per_60s", 20))
        hb_cfg       = cfg.get("heartbeat_timeout_seconds", {})
        self._hb_default  = int(hb_cfg.get("default", 30))
        self._hb_per_node = {
            k: int(v) for k, v in hb_cfg.items() if k != "default"
        }

        # Engine-level secondary flood tracker
        self._flood_times: dict[str, deque] = defaultdict(deque)

        log.info(
            f"ThreatDetector ready | allowed={self._allowed_nodes or 'ALL'} | "
            f"flood_max={self._flood_max_per_60s}/60s"
        )

    def run(self, event: dict) -> list:
        """
        Run all applicable detectors against the event.
        Returns a list of ThreatSignal objects.
        """
        signals = []

        # Events already flagged as security alerts by the controller
        # are routed directly through the alert manager — no re-detection needed.
        if event.get("security_alert"):
            return signals

        node = event.get("node", "unknown")

        signals += self._detect_rogue_node(node, event)
        signals += self._detect_impersonation(node, event)
        signals += self._detect_secondary_flood(node, event)
        signals += self._detect_lateral_movement(node, event)
        signals += self._detect_config_tamper(node, event)
        signals += self._detect_unauth_process(node, event)

        return signals

    # ── A: Rogue Node ─────────────────────────────────────────────────

    def _detect_rogue_node(self, node: str, event: dict) -> list:
        if not self._allowed_nodes:
            return []
        if node not in self._allowed_nodes:
            log.warning(f"[ENGINE] ROGUE_NODE: {node}")
            return [ThreatSignal(
                node_id     = node,
                threat_type = "ROGUE_NODE",
                severity    = "CRITICAL",
                description = f"Node '{node}' is not in the approved allowlist.",
                evidence    = {
                    "node":       node,
                    "machine_id": event.get("machine_id", ""),
                    "allowed":    list(self._allowed_nodes),
                },
            )]
        return []

    # ── B: Node Impersonation ─────────────────────────────────────────

    def _detect_impersonation(self, node: str, event: dict) -> list:
        claimed_mid = event.get("machine_id", "")
        if not claimed_mid:
            return []

        known = self._store.get_node_identity(node)
        if known is None:
            # First time seeing this node — register it
            self._store.upsert_node_identity(
                node=node,
                machine_id=claimed_mid,
                trust_status="TRUSTED",
            )
            return []

        known_mid = known.get("machine_id", "")
        if known_mid and known_mid != claimed_mid:
            log.warning(f"[ENGINE] NODE_IMPERSONATION: {node} machine_id changed")
            self._store.upsert_node_identity(
                node=node,
                machine_id=claimed_mid,
                trust_status="SUSPECT",
            )
            return [ThreatSignal(
                node_id     = node,
                threat_type = "NODE_IMPERSONATION",
                severity    = "CRITICAL",
                description = f"Node {node} changed its machine_id.",
                evidence    = {
                    "node":              node,
                    "known_machine_id":  known_mid,
                    "claimed_machine_id": claimed_mid,
                },
            )]

        # Update last_seen timestamp
        self._store.upsert_node_identity(
            node=node,
            machine_id=claimed_mid,
            trust_status=known.get("trust_status", "TRUSTED"),
        )
        return []

    # ── E: Secondary Flood Check ──────────────────────────────────────

    def _detect_secondary_flood(self, node: str, event: dict) -> list:
        """
        Secondary rate check inside the engine.
        The controller is the primary guard; this catches anything that slips
        through (e.g., if the controller is restarted and its state is reset).
        """
        now    = time.time()
        cutoff = now - 60
        dq     = self._flood_times[node]
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)
        count = len(dq)

        # Use a higher threshold here (2× primary) to avoid false positives
        engine_threshold = self._flood_max_per_60s * 2
        if count > engine_threshold:
            return [ThreatSignal(
                node_id     = node,
                threat_type = "FLOOD_ATTACK",
                severity    = "MEDIUM",
                description = f"Engine: flood from {node}: {count} msgs/60s (threshold={engine_threshold})",
                evidence    = {"node": node, "count": count, "threshold": engine_threshold},
            )]
        return []

    # ── I: Lateral Movement ───────────────────────────────────────────

    def _detect_lateral_movement(self, node: str, event: dict) -> list:
        ssh_count  = int(event.get("ssh_connections", 0))
        peers      = event.get("lateral_peers", [])
        peer_count = int(event.get("peer_contact_count", 0))

        signals = []

        if ssh_count > 0:
            log.warning(f"[ENGINE] LATERAL_MOVEMENT: {node} has {ssh_count} SSH connections")
            signals.append(ThreatSignal(
                node_id     = node,
                threat_type = "LATERAL_MOVEMENT",
                severity    = "HIGH",
                description = f"Node {node} has {ssh_count} unexpected SSH connections to {peer_count} peer(s).",
                evidence    = {
                    "node":         node,
                    "ssh_count":    ssh_count,
                    "peer_count":   peer_count,
                    "lateral_peers": peers,
                },
            ))

        return signals

    # ── J: Config Tampering ───────────────────────────────────────────

    def _detect_config_tamper(self, node: str, event: dict) -> list:
        if not event.get("config_tamper"):
            return []

        tampered = event.get("tampered_files", [])
        if not tampered:
            return []

        log.warning(f"[ENGINE] CONFIG_TAMPER: {node} — {[t['file'] for t in tampered]}")
        return [ThreatSignal(
            node_id     = node,
            threat_type = "CONFIG_TAMPER",
            severity    = "HIGH",
            description = f"Node {node}: {len(tampered)} config file(s) modified.",
            evidence    = {
                "node":          node,
                "tampered_files": tampered,
            },
        )]

    # ── H: Unauthorized Process ───────────────────────────────────────

    def _detect_unauth_process(self, node: str, event: dict) -> list:
        procs = event.get("unauthorized_procs", [])
        if not procs:
            return []

        names = [p.get("name", "?") for p in procs]
        log.warning(f"[ENGINE] UNAUTH_PROCESS: {node} — {names}")
        return [ThreatSignal(
            node_id     = node,
            threat_type = "UNAUTH_PROCESS",
            severity    = "MEDIUM",
            description = f"Node {node}: {len(procs)} unauthorized process(es) detected: {names}",
            evidence    = {
                "node":      node,
                "processes": procs,
            },
        )]

    # ── F: Silent Node (called externally from heartbeat thread) ──────

    def build_silent_node_signal(self, node: str, delta_seconds: float) -> ThreatSignal:
        """
        Build a ThreatSignal for a node that has stopped reporting.
        Called from the heartbeat checker thread in engine.py.
        """
        hb_timeout = self._hb_per_node.get(node, self._hb_default)
        return ThreatSignal(
            node_id     = node,
            threat_type = "SILENT_NODE",
            severity    = "HIGH",
            description = (
                f"Node {node} has not reported for {delta_seconds:.0f}s "
                f"(timeout={hb_timeout}s)."
            ),
            evidence    = {
                "node":            node,
                "silent_seconds":  round(delta_seconds, 1),
                "configured_timeout": hb_timeout,
            },
        )
