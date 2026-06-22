"""
Always-On Security — Risk Engine (Enhanced with Security Layer)

Changes from baseline:
  - Integrates ThreatDetector and AlertManager
  - Routes controller-injected security alerts directly to AlertManager
  - Runs all threat detectors on each event
  - Enhanced heartbeat checker emits ThreatSignals via AlertManager
  - Updated REQUIRED_FIELDS for new secure telemetry envelope
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
from cmd_server import run_cmd_server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("engine")

CONFIG = "/opt/security/config"

# Fields required in every validated telemetry message.
# Security envelope fields (msg_id, seq, timestamp, machine_id) are
# preferred but optional at the engine level — the controller is the
# enforcer. We keep _offset as mandatory.
REQUIRED_FIELDS = {
    "node", "cpu_usage", "memory_usage",
    "process_count", "event_type", "reasons", "_offset",
}

# Track when each node was last seen (for heartbeat)
node_last_seen      = {}
node_last_seen_lock = threading.Lock()

NODE_LIST         = ["node1", "node2", "node3", "node4"]
HEARTBEAT_TIMEOUT = 30  # seconds — default; per-node config read by ThreatDetector


def validate(event: dict) -> bool:
    """Check that all required fields are present."""
    # Security-alert synthetic events from controller don't carry hardware fields
    if event.get("security_alert"):
        return "node" in event and "_offset" in event
    return REQUIRED_FIELDS.issubset(event.keys())


def heartbeat_checker(
    store: Store,
    threat_detector: ThreatDetector,
    alert_manager: AlertManager,
    router: Router,
):
    """
    Detects nodes that have stopped sending telemetry.
    Runs in a background thread, checking every 10 seconds.
    Now emits structured SecurityAlert records via AlertManager.
    """
    log.info(f"Heartbeat checker running (timeout={HEARTBEAT_TIMEOUT}s)")
    time.sleep(15)  # Give nodes time to start

    while True:
        now = datetime.now()
        with node_last_seen_lock:
            for node in NODE_LIST:
                status = store.get_node_status(node)
                if status in ("awaiting_approval", "quarantined", "unresponsive"):
                    continue

                last = node_last_seen.get(node)
                if last is None:
                    continue
                delta = (now - last).total_seconds()
                if delta > HEARTBEAT_TIMEOUT:
                    log.warning(
                        f"HEARTBEAT: {node} unresponsive "
                        f"({delta:.0f}s since last telemetry)"
                    )
                    try:
                        store.write_heartbeat_event(node=node, delta_seconds=delta)
                        signal = threat_detector.build_silent_node_signal(node, delta)
                        alert_manager.emit(signal)
                        router._quarantine(node)
                    except Exception as e:
                        log.error(f"Heartbeat processing error: {e}")
        time.sleep(10)


def main():
    store = Store()

    correlator  = Correlator(window_seconds=600, threshold_nodes=3, multiplier=1.5)
    past_events = store.warm_restart_events(window_seconds=600)
    correlator.warm_restart(past_events)

    pipeline = Pipeline(
        enricher  = Enricher(store),
        correlator= correlator,
        rules     = RuleEngine.from_yaml(f"{CONFIG}/rules.yaml"),
        scorer    = WeightedScorer.from_yaml(
            f"{CONFIG}/thresholds.yaml",
            f"{CONFIG}/node_criticality.yaml",
        ),
        router    = Router.from_yaml(f"{CONFIG}/thresholds.yaml", store=store),
    )

    threat_detector = ThreatDetector(store)
    alert_manager   = AlertManager(store)

    engine_state = {"last_offset": store.last_committed_offset()}
    log.info(f"Risk engine ready — resuming from offset {engine_state['last_offset']}")

    # Start cmd server thread
    cmd_thread = threading.Thread(
        target=run_cmd_server,
        args=(store, pipeline.router, engine_state),
        name="CmdServer",
        daemon=True,
    )
    cmd_thread.start()
    log.info("Started cmd server thread")

    # Start heartbeat checker thread
    hb_thread = threading.Thread(
        target=heartbeat_checker,
        args=(store, threat_detector, alert_manager, pipeline.router),
        name="HeartbeatChecker",
        daemon=True,
    )
    hb_thread.start()
    log.info("Started heartbeat checker thread")

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
            log.warning(
                f"Dropped malformed event (missing fields): "
                f"{sorted(event.keys())}"
            )
            continue

        offset = event["_offset"]
        if offset <= engine_state["last_offset"]:
            log.debug(f"Skipping replayed offset {offset} (committed={engine_state['last_offset']})")
            continue

        # Update heartbeat tracking
        node = event.get("node", "unknown")
        with node_last_seen_lock:
            node_last_seen[node] = datetime.now()

        # ── Route controller-injected security alerts directly ────────
        if event.get("security_alert"):
            alert = alert_manager.emit_from_event(event)
            if alert:
                log.info(
                    f"[CONTROLLER_ALERT] {alert.threat_type} | "
                    f"node={alert.node_id} | severity={alert.severity}"
                )
            # FIX #8: Persist offset to DB so warm-restart skips replayed events.
            store.conn.execute(
                "UPDATE engine_offset SET last_committed=? WHERE id=1", (offset,)
            )
            store.conn.commit()
            engine_state["last_offset"] = offset
            continue

        # ── Standard telemetry pipeline ───────────────────────────────
        try:
            decision = pipeline.process(event)
            store.write_event(event, decision)
            engine_state["last_offset"] = offset

            # Update node status
            status = "idle"
            if event.get("is_busy"):
                status = "busy"
            if decision.bucket == "quarantine":
                status = "quarantined"
            elif decision.bucket == "human":
                status = "awaiting_approval"
            store.update_node_status(
                node=node,
                status=status,
                risk_score=decision.cumulative_score,
            )

            pipeline.router.dispatch(decision)

            # ── Run threat detectors ──────────────────────────────────
            signals = threat_detector.run(event)
            if signals:
                alerts = alert_manager.emit_batch(signals)
                log.info(f"Emitted {len(alerts)} threat alert(s) for node={node}")
                if any(alert.severity == "CRITICAL" for alert in alerts):
                    log.critical(
                        f"Critical threat detected for node={node}; "
                        "initiating immediate quarantine"
                    )
                    pipeline.router._quarantine(node)

        except Exception as e:
            log.error(
                f"Pipeline error at offset {offset}: {e}",
                exc_info=True,
            )


if __name__ == "__main__":
    main()
