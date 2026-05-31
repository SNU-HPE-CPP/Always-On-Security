import time
import logging
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


@dataclass
class Decision:
    node: str
    event_offset: int
    event_score: float
    cumulative_score: float
    bucket: str
    matched_rules: list          # list of (rule_id, severity, blast_radius)
    correlated: bool
    raw_event: dict


class Pipeline:
    def __init__(self, enricher, correlator, rules, scorer, router):
        self.enricher = enricher
        self.correlator = correlator
        self.rules = rules
        self.scorer = scorer
        self.router = router

    def process(self, event: dict) -> Decision:
        node = event.get("node", "unknown")
        offset = event.get("_offset", 0)

        # Step 2: enrich with SQLite context (score, incident count)
        event = self.enricher.enrich(event)
        current_score = event["_current_score"]

        # Step 4: rule matching
        matches = self.rules.match(event)

        # Step 3: cross-node correlation (checked per matched rule)
        correlated = False
        multiplier = 1.0
        now = time.time()
        for rule_id, _, _ in matches:
            c, m = self.correlator.check(rule_id, node, now)
            if c:
                correlated = True
                multiplier = max(multiplier, m)

        # Step 5: weighted scoring
        event_score, new_cumulative, bucket = self.scorer.score(
            matches, node, current_score, multiplier
        )

        return Decision(
            node=node,
            event_offset=offset,
            event_score=event_score,
            cumulative_score=new_cumulative,
            bucket=bucket,
            matched_rules=matches,
            correlated=correlated,
            raw_event=event,
        )
