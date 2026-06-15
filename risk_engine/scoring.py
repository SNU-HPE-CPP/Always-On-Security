import logging
import yaml

log = logging.getLogger(__name__)


class WeightedScorer:
    def __init__(self, buckets: dict, criticality: dict, default_criticality: int = 15, decay_rate: float = 5.0):
        self.buckets = buckets          # {name: [lo, hi]}
        self.criticality = criticality  # {node: int}
        self.default_criticality = default_criticality
        self.decay_rate = decay_rate

    @classmethod
    def from_yaml(cls, thresholds_path: str, criticality_path: str) -> "WeightedScorer":
        with open(thresholds_path) as f:
            cfg = yaml.safe_load(f)
        with open(criticality_path) as f:
            crit_raw = yaml.safe_load(f) or {}
        default = int(crit_raw.pop("default", 15))
        crit = {k: int(v) for k, v in crit_raw.items()}
        decay_rate = float(cfg.get("decay_rate", 5.0))
        return cls(cfg["buckets"], crit, default, decay_rate)

    def asset_criticality(self, node: str) -> int:
        return self.criticality.get(node, self.default_criticality)

    def score(
        self,
        matches: list[tuple[str, int, int]],
        node: str,
        current_score: float,
        multiplier: float = 1.0,
    ) -> tuple[float, float, str]:
        import time
        if not hasattr(self, 'fim_hold_until'):
            self.fim_hold_until = {}

        if not matches:
            # If we are under a FIM decay hold, skip decay
            if node in self.fim_hold_until and time.time() < self.fim_hold_until[node]:
                bucket = self._bucket(current_score)
                return 0.0, round(current_score, 4), bucket

            # Risk decay for normal events (Sukhraj's feature)
            new_cumulative = max(0.0, current_score - self.decay_rate)
            bucket = self._bucket(new_cumulative)
            return 0.0, round(new_cumulative, 4), bucket

        # Check if any matched rule is FIM-related
        is_fim = any(rule_id.startswith("FIM_") for rule_id, _, _ in matches)
        if is_fim:
            # Set decay hold for 300 seconds (5 minutes)
            self.fim_hold_until[node] = time.time() + 300

        ac = self.asset_criticality(node)
        # Take the highest-scoring rule to avoid double-counting
        event_score = max(
            sev * br * ac / 1000
            for _, sev, br in matches
        ) * multiplier

        new_cumulative = current_score + event_score
        bucket = self._bucket(new_cumulative)

        log.debug(
            f"node={node} ac={ac} matches={[r[0] for r in matches]} "
            f"event_score={event_score:.4f} cumulative={new_cumulative:.4f} bucket={bucket}"
        )
        return round(event_score, 4), round(new_cumulative, 4), bucket

    def _bucket(self, score: float) -> str:
        # We rely on dictionary insertion order (silent, auto, human).
        # By only checking the upper bound (+1 to close the decimal gap), we prevent floats from falling through.
        for name, bounds in self.buckets.items():
            hi = bounds[1]
            if score < hi + 1.0:
                return name
        return "quarantine"  # score >= 101.0
