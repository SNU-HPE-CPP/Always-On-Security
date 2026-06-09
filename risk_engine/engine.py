"""
Always-On Security — Risk Engine (with Security Layer)
Integrates ThreatDetector and AlertManager alongside standard telemetry pipeline.
"""
import time
import logging
import threading
import zmq
from datetime import datetime, timezone

from store import Store
from enrichment import Enricher
from correlation import Correlator
from rules import RuleEngine
from scoring import WeightedScorer
from router import Router
from pipeline import Pipeline
from threat_detector import ThreatDetector
from alert_manager import AlertManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("engine")

CONFIG = "/opt/security/config"

REQUIRED_FIELDS = {"node", "cpu_usage", "memory_usage", "process_count", "event_type", "reasons", "_offset"}

node_last_seen      = {}
node_last_seen_lock = threading.Lock()
NODE_LIST           = ["node1", "node2", "node3", "node4"]
HEARTBEAT_TIMEOUT   = 30


def validate(event: dict) -> bool:
    if event.get("security_alert"):
        return "node" in event and "_offset" in event
    return REQUIRED_FIELDS.issubset(event.keys())


def heartbeat_checker(store: Store, threat_detector: ThreatDetector, alert_manager: AlertManager):
    log.info(f"Heartbeat checker running (timeout={HEARTBEAT_TIMEOUT}s)")
    time.sleep(15)
    while True:
        now = datetime.now()
        with node_last_seen_lock:
            for node in NODE_LIST:
                last = node_last_seen.get(node)
                if last is None:
                    continue
                delta = (now - last).total_seconds()
                if delta > HEARTBEAT_TIMEOUT:
                    log.warning(f"HEARTBEAT: {node} unresponsive ({delta:.0f}s)")
                    try:
                        store.write_heartbeat_event(node=node, delta_seconds=delta)
                        signal = threat_detector.build_silent_node_signal(node, delta)
                        alert_manager.emit(signal)
                    except Exception as e:
                        log.error(f"Heartbeat error: {e}")
        time.sleep(10)


def main():
    store = Store()

    correlator  = Correlator(window_seconds=600, threshold_nodes=3, multiplier=1.5)
    past_events = store.warm_restart_events(window_seconds=600)
    correlator.warm_restart(past_events)

    pipeline = Pipeline(
        enricher   = Enricher(store),
        correlator = correlator,
        rules      = RuleEngine.from_yaml(f"{CONFIG}/rules.yaml"),
        scorer     = WeightedScorer.from_yaml(f"{CONFIG}/thresholds.yaml", f"{CONFIG}/node_criticality.yaml"),
        router     = Router.from_yaml(f"{CONFIG}/thresholds.yaml"),
    )

    threat_detector = ThreatDetector(store)
    alert_manager   = AlertManager(store)
    last_offset     = store.last_committed_offset()
    log.info(f"Risk engine ready — resuming from offset {last_offset}")

    hb_thread = threading.Thread(
        target=heartbeat_checker, args=(store, threat_detector, alert_manager),
        name="HeartbeatChecker", daemon=True,
    )
    hb_thread.start()

    ctx  = zmq.Context()
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
            log.warning(f"Dropped malformed event: {sorted(event.keys())}")
            continue

        offset = event["_offset"]
        if offset <= last_offset:
            continue

        node = event.get("node", "unknown")
        with node_last_seen_lock:
            node_last_seen[node] = datetime.now()

        # Controller-injected security alerts bypass pipeline
        if event.get("security_alert"):
            alert = alert_manager.emit_from_event(event)
            if alert:
                log.info(f"[CONTROLLER_ALERT] {alert.threat_type} | node={alert.node_id} | {alert.severity}")
            last_offset = offset
            continue

        try:
            decision = pipeline.process(event)
            store.write_event(event, decision)
            last_offset = offset

            status = "idle"
            if event.get("is_busy"):
                status = "busy"
            if decision.bucket == "quarantine":
                status = "quarantined"
            store.update_node_status(node=node, status=status, risk_score=decision.cumulative_score)
            pipeline.router.dispatch(decision)

            signals = threat_detector.run(event)
            if signals:
                alerts = alert_manager.emit_batch(signals)
                log.info(f"Emitted {len(alerts)} threat alert(s) for node={node}")

        except Exception as e:
            log.error(f"Pipeline error at offset {offset}: {e}", exc_info=True)


if __name__ == "__main__":
    main()
