import logging
import zmq
from datetime import datetime, timezone

from store import Store
from enrichment import Enricher
from correlation import Correlator
from rules import RuleEngine
from scoring import WeightedScorer
from router import Router
from pipeline import Pipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("engine")

CONFIG = "/opt/security/config"

REQUIRED_FIELDS = {
    "node", "cpu_usage", "memory_usage",
    "process_count", "event_type", "reasons", "_offset",
}


def validate(event: dict) -> bool:
    return REQUIRED_FIELDS.issubset(event.keys())


def main():
    store = Store()

    correlator = Correlator(window_seconds=600, threshold_nodes=3, multiplier=1.5)
    past_events = store.warm_restart_events(window_seconds=600)
    correlator.warm_restart(past_events)

    pipeline = Pipeline(
        enricher=Enricher(store),
        correlator=correlator,
        rules=RuleEngine.from_yaml(f"{CONFIG}/rules.yaml"),
        scorer=WeightedScorer.from_yaml(
            f"{CONFIG}/thresholds.yaml",
            f"{CONFIG}/node_criticality.yaml",
        ),
        router=Router.from_yaml(f"{CONFIG}/thresholds.yaml"),
    )

    last_offset = store.last_committed_offset()
    log.info(f"Risk engine ready — resuming from offset {last_offset}")

    ctx = zmq.Context()
    sock = ctx.socket(zmq.PULL)
    sock.bind("tcp://*:5556")
    log.info("Listening on tcp://*:5556")

    while True:
        try:
            event = sock.recv_json()
        except Exception as e:
            log.error(f"ZMQ recv error: {e}")
            continue

        if not validate(event):
            log.warning(f"Dropped malformed event (missing fields): {sorted(event.keys())}")
            continue

        offset = event["_offset"]
        if offset <= last_offset:
            log.debug(f"Skipping replayed offset {offset} (committed={last_offset})")
            continue

        try:
            decision = pipeline.process(event)
            store.write_event(event, decision)
            last_offset = offset
            pipeline.router.dispatch(decision)
        except Exception as e:
            log.error(f"Pipeline error at offset {offset}: {e}", exc_info=True)


if __name__ == "__main__":
    main()
