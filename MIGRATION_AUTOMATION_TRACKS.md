# Post-Mortem & Architecture Debugging Report: Fixing Simulation and Telemetry Drops

## Overview

This document serves as an extensive report on the critical bugs that were discovered and fixed during the transition to the `automation-tracks` architecture. The issues primarily manifested as missing alerts, risk scores failing to increase during real attack simulations, and missing auto-remediation logs in the Next.js Dashboard UI.

---

## 1. Issue: Real Attack Simulations Dropped & No Risk Score Increase

### What Was Broken
When launching real simulations (e.g., executing a reverse shell or spawning an unexpected `exec`), the `security-monitor` successfully detected the event. However, these alerts never appeared in the Dashboard, and the corresponding risk score never increased. This was traced back to three overlapping architectural flaws in the telemetry pipeline:

1. **ReplayGuard Sequence Reset:** The `secure_messenger.py` component was initializing its message sequence counter (`_seq`) to `0` every time a node agent or container restarted. The `Controller`'s ReplayGuard strict checks saw these resetting sequences as duplicate messages (Replay Attacks) and silently dropped the critical telemetry.
2. **FloodGuard Triggering:** The `docker_collector` was aggressively sending every minor lifecycle event (`exec_create`, `exec_die`, `disconnect`) to the `event_forwarder`. This overwhelmed the Controller's rate limit of 20 messages per 60 seconds. Consequently, the FloodGuard blacklisted the node and dropped the alerts.
3. **Malformed Payload Structure:** Even when events bypassed the gate, the `event_forwarder` sent them under the `threat_type` key. The Risk Engine's scoring logic, however, specifically required the keys `event_type` and `reasons` to properly route and aggregate the score.

### How We Fixed It
* **Monotonic Sequencing:** We modified `secure_messenger.py` to initialize the sequence based on the epoch time: `self._seq = int(time.time() * 1000)`. This guarantees that even if a container restarts, its sequence number strictly increases, seamlessly bypassing the ReplayGuard.
* **Client-Side Rate Limiting:** We implemented a `_rate_ok()` token bucket in `event_forwarder.py` to throttle outgoing events to a maximum of 15 messages per 60 seconds per node. Additionally, we filtered the `docker_collector` to transmit only high-value events (`exec_start` and `connect`), preventing the FloodGuard from triggering.
* **Payload Normalization:** We updated `event_forwarder.py` to correctly map the ZMQ payload: injecting `event_type: event.get("threat_type")` and `reasons: [event.get("threat_type")]`. This ensured the Risk Engine processed and scored the alerts properly.

---

## 2. Issue: Missing Auto-Remediation Logs & Human Approval Auto-Closing

### What Was Broken
During the multi-signal demo, the node was successfully quarantined. However, the "Auto-Remediation" execution logs (e.g., the standard output of `kill -9` or `iptables` playbooks) were completely missing from the incident history timeline. Furthermore, clicking the Human Approval buttons in the UI was malfunctioning—the UI state would auto-close unpredictably. This occurred because the `events.db` SQLite store lacked the necessary query pathways to serve historical and stateful context back to the Next.js API.

### How We Fixed It
* **Incident History Query:** We implemented the `get_node_event_history(node, limit)` method in `risk_engine/store.py`. This enabled the Dashboard UI to fetch a chronologically ordered event timeline (including `weighted_score`, `correlated` flags, and `reasons`). As a result, the auto-remediation playbook logs now successfully render in the UI.
* **Human Review Tracking:** We added the `write_review_decision()` method to `store.py`. Now, when an analyst clicks Approve or Deny in the Dashboard, the SQLite database permanently records the `review_notes`, `reviewed_by`, and `reviewed_at` timestamps inside the `node_status` table. This established a robust audit trail and resolved the UI's unpredictable auto-closing behavior by anchoring its state to the database.

---

## 3. Issue: Obsolete Configuration Checks & Unnecessary Zeek Noise

### What Was Broken
The system's pre-flight integrity script, `check_config_integrity.py`, was crashing because it was attempting to hash `allowlist.yaml` and `thresholds.yaml`—files we had already deleted and consolidated. Additionally, `zeek_emulator.py` was generating false-positive `Unexpected Listener` alerts for internal Docker DNS traffic originating from `127.0.0.11`.

### How We Fixed It
* **Config Consolidation:** We removed the obsolete YAML references from the `SERVICE_CONFIG_FILES` list in `check_config_integrity.py` and updated the system to track the unified `master_config.yaml`.
* **Zeek Filtering:** We added an explicit IP exclusion condition for `127.0.0.11` within `zeek_emulator.py`, eliminating the network noise and preventing false-positive risk score inflation.
