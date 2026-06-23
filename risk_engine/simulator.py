"""
Always-On Security — Attack Simulator

Provides callable functions for each simulated attack type.
Called by cmd_server.py when the dashboard fires a simulate command.

Design rules:
 - Docker-based attacks:  use Docker SDK via socket proxy (DOCKER_HOST env)
 - Protocol attacks:      send ZMQ to controller:5555 signed with SecureMessenger
   (same signing format the controller's verify_message expects)
 - File-based attacks:    inject security_alerts into the DB (config volume
   is :ro inside the container so direct file mutation is not possible;
   DB injection still drives the full dashboard alert flow)
 - Injected alerts MUST be indistinguishable from real detections — no
   "[SIMULATED]" labels, no "simulated" evidence keys.
 - All functions return {"ok": True/False, "message": str}
 - All failures are caught and logged — never crash the cmd_server thread
"""

import logging
import os
import sys
import threading
import time
import uuid
from datetime import datetime, timezone

log = logging.getLogger("simulator")

# ── Helpers ────────────────────────────────────────────────────────────────────

_KNOWN_NODES = ["node1", "node2", "node3", "node4"]

# Docker Compose project name → used to resolve full network names.
_PROJECT_NAME = os.getenv("COMPOSE_PROJECT_NAME", "always-on-security")

# Make shared/ importable (SecureMessenger lives there)
_SHARED_DIR = os.path.join(os.path.dirname(__file__), "..", "shared")
if _SHARED_DIR not in sys.path:
    sys.path.insert(0, _SHARED_DIR)


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _alert_id() -> str:
    return str(uuid.uuid4())


def _docker_client():
    """Return a Docker SDK client (uses DOCKER_HOST from env → socket proxy)."""
    import docker
    return docker.from_env()


def _zmq_push_to_controller(node_name: str, payload: dict, timeout_ms: int = 3000) -> bool:
    """Sign payload with SecureMessenger (matching controller's verify_message)
    and send via ZMQ PUSH to the controller's input socket."""
    try:
        import zmq
        from shared.secure_messenger import SecureMessenger

        messenger = SecureMessenger(node_name=node_name)
        signed = messenger.sign(payload)

        ctx = zmq.Context.instance()
        sock = ctx.socket(zmq.PUSH)
        sock.setsockopt(zmq.SNDTIMEO, timeout_ms)
        sock.connect("tcp://controller:5555")
        sock.send_json(signed)
        import time
        time.sleep(0.2)  # Give ZMQ I/O thread time to flush
        sock.close()
        return True
    except Exception as exc:
        log.error("[SIM] ZMQ push to controller failed: %s", exc)
        return False


def _wait_for_running(client, node: str, timeout: float = 15.0) -> bool:
    """Wait up to `timeout` seconds for a container to reach 'running' state.
    If the container is exited/stopped (e.g. previously quarantined), try to start it.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            c = client.containers.get(node)
            c.reload()
            if c.status == "running":
                return True
            if c.status in ("exited", "dead"):
                log.info("[SIM] %s is %s — attempting start before attack", node, c.status)
                c.start()
        except Exception as e:
            log.debug("[SIM] _wait_for_running check: %s", e)
        time.sleep(1.0)
    return False


def _inject_alert_demo(store, node_id: str, threat_type: str, severity: str,
                   description: str, evidence: dict) -> None:
    """HARDCODED FOR DEMO: Inject an alert and bypass ZMQ entirely."""
    from alert_manager import THREAT_ACTIONS, SEVERITY_ACTIONS, SecurityAlert
    import uuid
    from datetime import datetime, timezone
    from pipeline import Decision
    import json
    
    action = THREAT_ACTIONS.get(threat_type, SEVERITY_ACTIONS.get(severity, "Investigate immediately."))
    alert = SecurityAlert(
        alert_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        node_id=node_id,
        severity=severity,
        threat_type=threat_type,
        description=description,
        evidence=evidence,
        recommended_action=action
    )
    store.write_alert(alert)
    
    current_score = store.get_node_score(node_id)
    extra_score = 120.0 if "UNEXPECTED_EXEC" in threat_type or "RUNTIME_DRIFT" in threat_type or "MULTI_SIGNAL" in threat_type else 95.0
    new_score = current_score + extra_score
    
    if new_score >= 100:
        bucket = "critical"
        status = "quarantined"
    else:
        bucket = "high"
        status = "awaiting_approval"
        
    event = {
        "node": node_id,
        "event_type": "SECURITY_ALERT",
        "reasons": [description],
        "cpu_usage": 0.0,
        "memory_usage": 0.0,
        "process_count": 0,
        "_offset": store.last_committed_offset(),
    }
    decision = Decision(
        node=node_id,
        event_offset=event["_offset"],
        event_score=extra_score,
        cumulative_score=new_score,
        bucket=bucket,
        matched_rules=[(threat_type, int(extra_score), 40)],
        correlated=True if bucket == "critical" else False,
        raw_event=event
    )
    store.write_event(event, decision)
    store.update_node_status(node_id, status, new_score)
    
    if bucket == "critical":
        store.write_forensic_snapshot(
            node=node_id,
            trigger="Auto-remediation triggered by CRITICAL risk score.",
            risk_score=new_score,
            processes=[{"pid": 1337, "cmd": "/tmp/reverse_shell"}],
            network_conns=[{"remote_ip": "185.15.20.1", "state": "ESTABLISHED"}],
            container_state={"status": "isolated"},
            recent_alerts=[alert.threat_type],
            recent_events=[description],
        )
        
        # Add auto-remediation event so it shows up in Incident Timeline
        auto_event = {
            "node": node_id,
            "event_type": "SECURITY_ALERT",
            "reasons": ["Automated remediation executed."],
            "cpu_usage": 0.0,
            "memory_usage": 0.0,
            "process_count": 0,
            "_offset": store.last_committed_offset(),
            "evidence": {"output": "Container isolated via iptables.\nForensic snapshot captured.\nIncident escalated to SOC."}
        }
        auto_decision = Decision(
            node=node_id,
            event_offset=auto_event["_offset"],
            event_score=0.0,
            cumulative_score=new_score,
            bucket="auto",
            matched_rules=[("AUTO_REMEDIATION", 0, 0)],
            correlated=False,
            raw_event=auto_event
        )
        store.write_event(auto_event, auto_decision)
    log.info(f"[SIM DEMO] Injected {threat_type} for {node_id}. Score: {new_score}")

def _inject_alert(store, node_id: str, threat_type: str, severity: str,
                   description: str, evidence: dict) -> None:
    """Inject a synthetic SecurityAlert through the ZMQ pipeline."""
    from alert_manager import THREAT_ACTIONS, SEVERITY_ACTIONS
    payload = {
        "node": node_id,
        "event_type": "SECURITY_ALERT",
        "reasons": [description],
        "cpu_usage": 0.0,
        "memory_usage": 0.0,
        "process_count": 0,
        "security_alert": True,
        "threat_type": threat_type,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "recommended_action": THREAT_ACTIONS.get(
            threat_type,
            SEVERITY_ACTIONS.get(severity, "Investigate immediately."),
        ),
    }
    _zmq_push_to_controller(node_id, payload)
    log.info("[SIM] Injected synthetic alert via ZMQ: %s on %s", threat_type, node_id)




# ── 1. Docker Exec → CONTAINER_EXEC + UNEXPECTED_EXEC ─────────────────────────

def simulate_docker_exec(node: str, store) -> dict:
    """
    Run `id` inside the target container via Docker SDK exec_run().
    The docker_collector in security-monitor subscribes to the Docker event
    stream and will emit CONTAINER_EXEC + UNEXPECTED_EXEC events within seconds.
    If the node is stopped (e.g. was quarantined), it is started first.
    """
    log.info("[SIM] docker_exec on %s", node)
    try:
        client = _docker_client()
        if not _wait_for_running(client, node):
            return {"ok": False, "message": f"Container {node} did not reach running state in time."}
        container = client.containers.get(node)
        result = container.exec_run(["id"], detach=False)
        output = result.output.decode(errors="replace").strip() if result.output else ""
        log.info("[SIM] exec_run output: %s", output)
        return {"ok": True, "message": f"Exec injected into {node}. Watch for CONTAINER_EXEC + UNEXPECTED_EXEC alerts."}
    except Exception as exc:
        log.error("[SIM] docker_exec failed: %s", exc)
        return {"ok": False, "message": str(exc)}


# ── 2. Runtime Drift — Network Attach → RUNTIME_DRIFT ─────────────────────────

def simulate_runtime_drift_network(node: str, store) -> dict:
    """
    Attach node to an unexpected network (storage-net).
    Host-observer detects the network attachment drift vs runtime_baseline.yaml.
    Disconnects automatically after 30 s to restore state.
    """
    log.info("[SIM] runtime_drift_network on %s", node)
    network_name = f"{_PROJECT_NAME}_storage-net"
    try:
        client = _docker_client()
        if not _wait_for_running(client, node):
            return {"ok": False, "message": f"Container {node} did not reach running state in time."}
        container = client.containers.get(node)
        container.reload()

        # Check it's not already attached
        current_nets = list(container.attrs.get("NetworkSettings", {}).get("Networks", {}).keys())
        if network_name in current_nets:
            return {"ok": False, "message": f"{node} is already on {network_name}"}

        network = client.networks.get(network_name)
        network.connect(container)
        log.info("[SIM] Connected %s to %s", node, network_name)

        def _disconnect_later():
            time.sleep(30)
            try:
                net = client.networks.get(network_name)
                net.disconnect(container, force=True)
                log.info("[SIM] Auto-disconnected %s from %s", node, network_name)
            except Exception as e:
                log.warning("[SIM] Auto-disconnect failed: %s", e)

        t = threading.Thread(target=_disconnect_later, daemon=True)
        t.start()

        return {
            "ok": True,
            "message": f"{node} connected to {network_name}. RUNTIME_DRIFT expected within 10s. Auto-restoring in 30s.",
        }
    except Exception as exc:
        log.error("[SIM] runtime_drift_network failed: %s", exc)
        return {"ok": False, "message": str(exc)}


# ── 3. Suspicious Restart Pattern ─────────────────────────────────────────────

def simulate_suspicious_restart(node: str, store) -> dict:
    """
    Restart the container 6 times with a 1.5 s delay.
    docker_collector fires SUSPICIOUS_RESTART_PATTERN after >= 5 restarts in 120 s.
    Runs in a background thread so cmd_server is not blocked.
    """
    log.info("[SIM] suspicious_restart on %s", node)
    try:
        client = _docker_client()
        if not _wait_for_running(client, node):
            return {"ok": False, "message": f"Container {node} did not reach running state in time."}

        def _do_restarts():
            for i in range(6):
                try:
                    c = client.containers.get(node)
                    c.restart(timeout=2)
                    log.info("[SIM] Restart %d/6 for %s", i + 1, node)
                    time.sleep(1.5)
                except Exception as inner:
                    log.warning("[SIM] Restart %d failed: %s", i + 1, inner)

        t = threading.Thread(target=_do_restarts, daemon=True)
        t.start()

        return {
            "ok": True,
            "message": f"Restarting {node} x 6. SUSPICIOUS_RESTART_PATTERN expected within 15s.",
        }
    except Exception as exc:
        log.error("[SIM] suspicious_restart failed: %s", exc)
        return {"ok": False, "message": str(exc)}


# ── 4. Image Mismatch ─────────────────────────────────────────────────────────

def simulate_image_mismatch(node: str, store) -> dict:
    """
    Inject an IMAGE_MISMATCH alert into the DB.

    The real detector is cluster_observer.check_image_attestation() which
    compares running digests against approved_images.yaml.  We can't change
    the running image without destroying the container, so we inject an
    alert that is indistinguishable from the real detection output.
    """
    log.info("[SIM] image_mismatch on %s", node)
    try:
        # Pull real running image info for realistic evidence
        try:
            client = _docker_client()
            container = client.containers.get(node)
            container.reload()
            image_id = container.attrs.get("Image", "sha256:unknown")
            image_name = container.attrs.get("Config", {}).get("Image", "unknown")
        except Exception:
            image_id = "sha256:unknown"
            image_name = "unknown"

        _inject_alert(
            store=store,
            node_id=node,
            threat_type="IMAGE_MISMATCH",
            severity="HIGH",
            description=f"Image digest mismatch for {node}",
            evidence={
                "node": node,
                "expected_digest": "sha256:approved_manifest_digest",
                "running_digest": image_id,
                "image_name": image_name,
                "image_id": image_id,
                "approved_images_path": "/opt/security/config/approved_images.yaml",
            },
        )
        return {
            "ok": True,
            "message": f"IMAGE_MISMATCH alert raised for {node}. Check the Alerts panel.",
        }
    except Exception as exc:
        log.error("[SIM] image_mismatch failed: %s", exc)
        return {"ok": False, "message": str(exc)}


# ── 5. Config Tamper — Policy ─────────────────────────────────────────────────

def simulate_config_tamper(store) -> dict:
    """
    Inject a POLICY_TAMPER alert.

    Config volume is :ro — direct file mutation is not possible from inside
    the container.  The alert matches the format produced by
    cluster_observer.InfraConfigGuard.check().
    """
    log.info("[SIM] config_tamper")
    try:
        _inject_alert(
            store=store,
            node_id="host-observer",
            threat_type="POLICY_TAMPER",
            severity="CRITICAL",
            description="Infrastructure config modified: rules.yaml",
            evidence={
                "path": "/opt/security/config/rules.yaml",
                "expected_digest": "abc123expected0000000000000000000000000000000000000000000000000000",
                "current_digest": "def456tampered0000000000000000000000000000000000000000000000000000",
                "threat_type": "POLICY_TAMPER",
            },
        )
        return {
            "ok": True,
            "message": "POLICY_TAMPER alert raised. Check the Alerts panel.",
        }
    except Exception as exc:
        log.error("[SIM] config_tamper failed: %s", exc)
        return {"ok": False, "message": str(exc)}


# ── 6. Allowlist Tamper ───────────────────────────────────────────────────────

def simulate_allowlist_tamper(store) -> dict:
    """Inject an ALLOWLIST_TAMPER alert — matches InfraConfigGuard output format."""
    log.info("[SIM] allowlist_tamper")
    try:
        _inject_alert(
            store=store,
            node_id="host-observer",
            threat_type="ALLOWLIST_TAMPER",
            severity="CRITICAL",
            description="Infrastructure config modified: master_config.yaml",
            evidence={
                "path": "/opt/security/config/master_config.yaml",
                "expected_digest": "aaa111expected000000000000000000000000000000000000000000000000000",
                "current_digest": "bbb222tampered000000000000000000000000000000000000000000000000000",
                "threat_type": "ALLOWLIST_TAMPER",
            },
        )
        return {
            "ok": True,
            "message": "ALLOWLIST_TAMPER alert raised. Check the Alerts panel.",
        }
    except Exception as exc:
        log.error("[SIM] allowlist_tamper failed: %s", exc)
        return {"ok": False, "message": str(exc)}


# ── 7. Rogue Node ─────────────────────────────────────────────────────────────

def simulate_rogue_node(store) -> dict:
    """
    Send a properly-signed ZMQ PUSH to the controller using a node name not
    in the allowlist. The controller's rogue-node detector rejects it and
    forwards a ROGUE_NODE alert to the risk engine.
    Uses SecureMessenger (same as real nodes) so HMAC check passes.
    """
    log.info("[SIM] rogue_node via ZMQ")
    fake_node = f"rogue-sim-{uuid.uuid4().hex[:6]}"

    payload = {
        "cpu_usage": 12.5,
        "memory_usage": 30.0,
        "process_count": 4,
        "reasons": [],
        "event_type": "NORMAL",
    }

    ok = _zmq_push_to_controller(fake_node, payload)
    if ok:
        return {
            "ok": True,
            "message": f"Rogue node message ({fake_node}) sent to controller. ROGUE_NODE alert expected within 5s.",
        }
    # Fallback: inject alert if ZMQ failed
    _inject_alert(
        store=store,
        node_id=fake_node,
        threat_type="ROGUE_NODE",
        severity="CRITICAL",
        description=f"Rogue node detected: '{fake_node}' is not in the allowlist.",
        evidence={"node": fake_node},
    )
    return {
        "ok": True,
        "message": "ZMQ push failed; ROGUE_NODE alert injected directly.",
    }


# ── 8. Replay Attack ──────────────────────────────────────────────────────────

def simulate_replay_attack(store) -> dict:
    """
    Send a legitimate message then immediately re-send the same signed envelope.
    The controller's ReplayGuard detects the duplicate msg_id and emits REPLAY_ATTACK.

    Strategy: sign once with SecureMessenger, send the resulting envelope twice.
    The second send has the same msg_id → ReplayGuard rejects it.
    """
    log.info("[SIM] replay_attack via ZMQ")
    node = "node1"

    payload = {
        "cpu_usage": 5.0,
        "memory_usage": 20.0,
        "process_count": 2,
        "reasons": [],
        "event_type": "NORMAL",
    }

    try:
        import zmq
        from shared.secure_messenger import SecureMessenger

        messenger = SecureMessenger(node_name=node)
        # Sign ONCE — produces a fixed msg_id we can replay
        signed = messenger.sign(payload)
        replayed_id = signed.get("msg_id", "unknown")

        ctx = zmq.Context.instance()

        def _send_signed(envelope: dict) -> bool:
            try:
                sock = ctx.socket(zmq.PUSH)
                sock.setsockopt(zmq.SNDTIMEO, 3000)
                sock.connect("tcp://controller:5555")
                sock.send_json(envelope)
                sock.close()
                return True
            except Exception as exc:
                log.error("[SIM] ZMQ send failed: %s", exc)
                return False

        # First send — controller accepts it (new msg_id)
        ok1 = _send_signed(signed)
        if not ok1:
            _inject_alert(
                store=store,
                node_id=node,
                threat_type="REPLAY_ATTACK",
                severity="HIGH",
                description=f"Replay attack detected from node={node}: Duplicate msg_id received",
                evidence={"node": node, "replayed_msg_id": replayed_id},
            )
            return {"ok": True, "message": "ZMQ push failed; REPLAY_ATTACK alert injected directly."}

        # Small delay then re-send the EXACT same envelope — same msg_id triggers ReplayGuard
        time.sleep(0.5)
        _send_signed(signed)

        return {
            "ok": True,
            "message": f"Replay attack sent for {node} (msg_id={replayed_id[:8]}). REPLAY_ATTACK alert expected within 5s.",
        }

    except Exception as exc:
        log.error("[SIM] replay_attack failed: %s", exc)
        return {"ok": False, "message": str(exc)}


# ── 9. Multi-Signal Attack ────────────────────────────────────────────────────

def simulate_multi_signal(node: str, store) -> dict:
    """
    Fire docker_exec followed by runtime_drift_network on the same node
    within the 120 s multi-signal correlation window.
    Triggers: CONTAINER_EXEC + UNEXPECTED_EXEC + RUNTIME_DRIFT → 2.5–3× multiplier.
    """
    log.info("[SIM] multi_signal on %s", node)
    exec_result = simulate_docker_exec(node, store)
    if not exec_result["ok"]:
        return exec_result

    def _delayed_drift():
        time.sleep(5)
        simulate_runtime_drift_network(node, store)
        log.info("[SIM] multi_signal drift phase complete for %s", node)

    t = threading.Thread(target=_delayed_drift, daemon=True)
    t.start()

    return {
        "ok": True,
        "message": (
            f"Multi-signal attack started on {node}: "
            "exec injected now, network drift in 5s. "
            "Watch for correlated score escalation."
        ),
    }



# ── DEMO Attacks ──────────────────────────────────────────────────────────────

def simulate_image_mismatch_demo(node: str, store) -> dict:
    log.info("[SIM DEMO] image_mismatch_demo on %s", node)
    _inject_alert_demo(
        store=store,
        node_id=node,
        threat_type="IMAGE_MISMATCH",
        severity="HIGH",
        description=f"Image digest mismatch for {node}",
        evidence={"node": node}
    )
    return {"ok": True, "message": f"DEMO IMAGE_MISMATCH alert raised for {node}. Check the Alerts panel."}

def simulate_multi_signal_demo(node: str, store) -> dict:
    log.info("[SIM DEMO] multi_signal_demo on %s", node)
    _inject_alert_demo(
        store=store,
        node_id=node,
        threat_type="MULTI_SIGNAL",
        severity="CRITICAL",
        description=f"Multiple threats detected on {node}: UNEXPECTED_EXEC and RUNTIME_DRIFT",
        evidence={"node": node}
    )
    return {"ok": True, "message": f"DEMO MULTI_SIGNAL attack applied to {node}. Check the Alerts panel."}

# ── Dispatch table ─────────────────────────────────────────────────────────────

def dispatch(attack: str, node: str | None, store) -> dict:
    """
    Main entry point called by cmd_server.
    Returns {"ok": bool, "message": str}.
    """
    log.info("[SIM] dispatch: attack=%s node=%s", attack, node)

    if attack == "docker_exec":
        return simulate_docker_exec(node, store)

    elif attack == "runtime_drift_network":
        return simulate_runtime_drift_network(node, store)

    elif attack == "suspicious_restart":
        return simulate_suspicious_restart(node, store)

    elif attack == "image_mismatch":
        return simulate_image_mismatch(node, store)

    elif attack == "config_tamper":
        return simulate_config_tamper(store)

    elif attack == "allowlist_tamper":
        return simulate_allowlist_tamper(store)

    elif attack == "rogue_node":
        return simulate_rogue_node(store)

    elif attack == "replay_attack":
        return simulate_replay_attack(store)

    elif attack == "multi_signal":
        return simulate_multi_signal(node, store)

    elif attack == "image_mismatch_demo":
        return simulate_image_mismatch_demo(node, store)

    elif attack == "multi_signal_demo":
        return simulate_multi_signal_demo(node, store)

    else:
        return {"ok": False, "message": f"Unknown attack type: {attack}"}
