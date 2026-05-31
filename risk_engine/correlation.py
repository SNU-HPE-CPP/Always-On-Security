import json
import time
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone

log = logging.getLogger(__name__)


class Correlator:
    def __init__(self, window_seconds: int = 600, threshold_nodes: int = 3, multiplier: float = 1.5):
        self.window_seconds = window_seconds
        self.threshold_nodes = threshold_nodes
        self.multiplier = multiplier
        # rule_id → deque of (timestamp_float, node_name)
        self._windows: dict[str, deque] = defaultdict(deque)

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

    def warm_restart(self, past_events: list) -> None:
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
        log.info(f"Correlation warm restart: loaded {loaded} rule entries from {len(past_events)} past events")
