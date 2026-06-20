"""
Always-On Security — Multi-Signal Correlator (Improvement 6)

Enhances the sliding-window correlator with:
  1. Cross-node correlation (original) — same rule fires on N nodes
  2. Multi-signal correlation           — specific combinations of different
     threat types on the same node within a configurable window trigger
     higher-confidence findings with elevated multipliers

Multi-signal rules (configurable in thresholds.yaml or hardcoded here):
  REVERSE_SHELL + NETWORK_THREAT      → High Confidence Compromise  (2.5x)
  FALCO_ALERT   + RUNTIME_DRIFT + NETWORK_THREAT → Critical Risk    (3.0x)
  CONTAINER_EXEC + PRIV_ESC_ATTEMPT   → Active Attack Chain          (2.5x)
  IMAGE_MISMATCH + RUNTIME_DRIFT      → Deployment Tamper             (2.0x)
  ALLOWLIST_TAMPER + ROGUE_NODE       → Coordinated Intrusion         (3.0x)
"""

from __future__ import annotations

import json
import time
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# Multi-signal correlation rules:
# Each rule is (frozenset of threat_types, per-node window_seconds, multiplier, label)
MULTI_SIGNAL_RULES: list[tuple[frozenset, int, float, str]] = [
    (frozenset({"REVERSE_SHELL", "NETWORK_THREAT"}),
     120, 2.5, "High Confidence Compromise"),
    (frozenset({"FALCO_ALERT", "RUNTIME_DRIFT", "NETWORK_THREAT"}),
     300, 3.0, "Critical Multi-Signal Risk"),
    (frozenset({"CONTAINER_EXEC", "PRIV_ESC_ATTEMPT"}),
     180, 2.5, "Active Attack Chain"),
    (frozenset({"IMAGE_MISMATCH", "RUNTIME_DRIFT"}),
     600, 2.0, "Deployment Tamper"),
    (frozenset({"ALLOWLIST_TAMPER", "ROGUE_NODE"}),
     600, 3.0, "Coordinated Intrusion"),
    (frozenset({"CONTAINER_ESCAPE_ATTEMPT", "PRIV_ESC_ATTEMPT"}),
     120, 3.0, "Container Escape Attempt"),
]


class Correlator:
    def __init__(
        self,
        window_seconds: int = 600,
        threshold_nodes: int = 3,
        multiplier: float = 1.5,
    ):
        self.window_seconds  = window_seconds
        self.threshold_nodes = threshold_nodes
        self.multiplier      = multiplier

        # Cross-node window: rule_id → deque of (timestamp_float, node_name)
        self._windows: dict[str, deque] = defaultdict(deque)

        # Per-node threat-type window for multi-signal detection:
        # node → deque of (timestamp_float, threat_type)
        self._node_signals: dict[str, deque] = defaultdict(deque)

    # ── Cross-node correlation (original) ────────────────────────────────────

    def _evict(self, rule_id: str, now: float) -> None:
        dq = self._windows[rule_id]
        cutoff = now - self.window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def check(self, rule_id: str, node: str, ts: float | None = None) -> tuple[bool, float]:
        now = ts if ts is not None else time.time()
        self._evict(rule_id, now)
        self._windows[rule_id].append((now, node))
        distinct_nodes = {n for _, n in self._windows[rule_id]}
        correlated = len(distinct_nodes) >= self.threshold_nodes
        factor = self.multiplier if correlated else 1.0
        if correlated:
            log.warning(
                f"CORRELATION detected rule={rule_id} nodes={distinct_nodes} "
                f"window={self.window_seconds}s multiplier={factor}"
            )
        return correlated, factor

    # ── Multi-signal correlation (Improvement 6) ─────────────────────────────

    def record_threat(self, node: str, threat_type: str, ts: float | None = None) -> None:
        """Record a threat signal for a node for multi-signal correlation."""
        now = ts if ts is not None else time.time()
        self._node_signals[node].append((now, threat_type))

    def check_multi_signal(self, node: str, ts: float | None = None) -> tuple[bool, float, str]:
        """
        Evaluate all multi-signal rules against recent threat history for `node`.
        Returns (correlated: bool, best_multiplier: float, matched_label: str).
        """
        now = ts if ts is not None else time.time()
        best_multi = 1.0
        best_label = ""
        matched    = False

        for (required_types, window, multiplier, label) in MULTI_SIGNAL_RULES:
            cutoff = now - window
            # Collect threat types seen for this node within the window
            recent = {
                ttype
                for stamp, ttype in self._node_signals[node]
                if stamp >= cutoff
            }
            if required_types.issubset(recent):
                matched    = True
                best_label = label
                if multiplier > best_multi:
                    best_multi = multiplier
                log.warning(
                    f"MULTI-SIGNAL CORRELATION node={node} "
                    f"rule='{label}' types={required_types} "
                    f"multiplier={multiplier}"
                )

        # Evict old signals (keep window clean)
        max_window = max(w for _, w, _, _ in MULTI_SIGNAL_RULES)
        dq = self._node_signals[node]
        cutoff = now - max_window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        return matched, best_multi, best_label

    # ── Warm restart ─────────────────────────────────────────────────────────

    def warm_restart(self, past_events: list) -> None:
        """
        Reload historical correlation windows from the DB after a restart.
        FIX #19: Clear existing windows before reloading to prevent double-counting
        when the engine restarts multiple times (e.g. crash-loop recovery).
        """
        self._windows.clear()
        loaded = 0
        for ev in past_events:
            rule_ids = []
            try:
                rule_ids = json.loads(ev.get("matched_rules") or "[]")
            except Exception:
                continue
            ts_str = ev.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
            except Exception:
                ts = time.time()
            node = ev.get("node", "unknown")
            for rule_id in rule_ids:
                self._windows[rule_id].append((ts, node))
                loaded += 1
        log.info(
            f"Correlation warm restart: loaded {loaded} rule entries "
            f"from {len(past_events)} past events"
        )
