import logging

log = logging.getLogger(__name__)


class Enricher:
    def __init__(self, store):
        self.store = store

    def enrich(self, event: dict) -> dict:
        node = event["node"]
        event["_current_score"] = self.store.get_node_score(node)
        event["_incident_count_7d"] = self.store.get_incident_count_7d(node)
        log.debug(
            f"Enriched node={node} score={event['_current_score']:.2f} "
            f"incidents_7d={event['_incident_count_7d']}"
        )
        return event
