# Always-On Security

A containerised, multi-layer security monitoring and enforcement platform for HPC air-gapped clusters. The system detects threats across four independent signal sources — Docker runtime events, kernel-level syscall traces (Falco), network traffic (Suricata + Zeek), and infrastructure configuration integrity — correlates them across a risk engine, and drives automated enforcement with a full SOC dashboard.

---

## Table of Contents

1. [Design Principles](#1-design-principles)
2. [Architecture Overview](#2-architecture-overview)
3. [Service Map](#3-service-map)
4. [Component Reference](#4-component-reference)
   - [Node Agent](#node-agent-node_agent)
   - [Shared Secure Messenger](#shared-secure-messenger-sharedsecure_messengerpy)
   - [Controller](#controller-controller)
   - [Host Observer](#host-observer-host_observer)
   - [Security Monitor](#security-monitor-security_monitor)
   - [Risk Engine](#risk-engine-risk_engine)
   - [Dashboard](#dashboard-dashboard)
   - [Alert Ingestor](#alert-ingestor-alert_ingestor)
5. [Detection Coverage](#5-detection-coverage)
6. [Risk Scoring & Enforcement](#6-risk-scoring--enforcement)
7. [Multi-Signal Correlation](#7-multi-signal-correlation)
8. [Fast-Path Policy Engine](#8-fast-path-policy-engine)
9. [Auto-Remediation Playbooks](#9-auto-remediation-playbooks)
10. [Attack Simulator](#10-attack-simulator)
11. [Configuration Files](#11-configuration-files)
12. [Database Schema](#12-database-schema)
13. [Build-Time Security Pipeline](#13-build-time-security-pipeline)
14. [Deployment](#14-deployment)
15. [Environment Variables](#15-environment-variables)

---

## 1. Design Principles

- **Tenant workload containers are untrusted.** No security agents run inside them; no secrets are exposed to them.
- **All detection is external.** Every signal comes from the Infrastructure Zone via Docker APIs, kernel syscalls, or passive network capture — never from code or files inside the workload container.
- **No enforcement action touches workload internals.** Pause, stop, and network-isolate all operate at the outer container abstraction layer.
- **Cryptographic integrity on every message.** All telemetry is HMAC-SHA256 signed. The controller verifies every message before it reaches the risk engine.
- **Shift-left security.** A full GitHub Actions CI/CD pipeline (secrets scan, SAST, SCA, IaC lint) runs on every push.

---

## 2. Architecture Overview

```
  INFRASTRUCTURE ZONE
  ┌──────────────────────────────────────────────────────────────────────────┐
  │                                                                          │
  │  ┌─────────────────────────┐      ┌─────────────────────────────────┐   │
  │  │    HOST OBSERVER        │      │      SECURITY MONITOR           │   │
  │  │  cluster_observer.py    │      │                                 │   │
  │  │                         │      │  docker_collector.py  ──┐       │   │
  │  │  1. Resource telemetry  │      │  falco_collector.py   ──┤       │   │
  │  │  2. Image attestation   │      │  network_collector.py ──┤       │   │
  │  │  3. Runtime drift       │      │  threat_correlator.py ──┤       │   │
  │  │  4. Infra config        │      │  policy_engine.py     ──┤       │   │
  │  │     integrity           │      │  event_forwarder.py   ──┘       │   │
  │  │                         │      │                                 │   │
  │  │  Via docker-socket-proxy│      │  Suricata (NIDS)                │   │
  │  └──────────┬──────────────┘      │  Zeek emulator (behavioural)    │   │
  │             │ ZMQ PUSH            └────────────────┬────────────────┘   │
  │             │ (HMAC-signed)                        │ ZMQ PUSH           │
  │             ▼                                      │ (HMAC-signed)      │
  │  ┌──────────────────────────────────────────────────────────────────┐   │
  │  │                        CONTROLLER                                 │   │
  │  │  controller/controller.py                                         │   │
  │  │  1. HMAC verify  2. Rogue node  3. Replay guard                   │   │
  │  │  4. Flood guard  5. Impersonation  6. Duplicate ID               │   │
  │  └──────────────────────────────┬────────────────────────────────────┘   │
  │                                 │ ZMQ PUSH (validated)               │   │
  │                                 ▼                                    │   │
  │  ┌──────────────────────────────────────────────────────────────────┐   │
  │  │                       RISK ENGINE                                 │   │
  │  │  engine.py · pipeline.py · scoring.py · rules.py                 │   │
  │  │  enrichment.py · correlation.py · threat_detector.py             │   │
  │  │  alert_manager.py · router.py · network_isolator.py              │   │
  │  │  remediation_engine.py · cmd_server.py · simulator.py            │   │
  │  │                                                                   │   │
  │  │  ──► SQLite (events.db)                                          │   │
  │  │  ──► Docker Socket Proxy (pause / stop / network disconnect)     │   │
  │  │  ──► Alert Ingestor UDP :5514                                    │   │
  │  └──────────────────────────────────────────────────────────────────┘   │
  │                                                                          │
  │  ┌──────────────────────────┐   ┌─────────────────────────────────┐     │
  │  │  Flask API (dashboard)   │   │  Next.js Frontend (aos-frontend) │     │
  │  │  dashboard/app.py :5000  │◄──│  dashboard/aos-dashboard/ :3000  │     │
  │  └──────────────────────────┘   └─────────────────────────────────┘     │
  │                                                                          │
  │  ┌───────────────────────────────────────────────────────────────────┐  │
  │  │  docker-socket-proxy  10.10.3.5:2375  (tecnativa/docker-socket-   │  │
  │  │  proxy) — allowlists Docker API endpoints per consumer            │  │
  │  └───────────────────────────────────────────────────────────────────┘  │
  └──────────────────────────────────────────────────────────────────────────┘

  WORKLOAD ZONE  (no secrets · no agents · no root · no docker.sock)
  ┌──────────────────────────────────────────────────────────────────────────┐
  │  node1 (10.10.1.21)   node2 (10.10.1.22)                                │
  │  node3 (10.10.1.23)   node4 (10.10.2.31)                                │
  │  UID 10001 — runs a simple simulated workload only                       │
  └──────────────────────────────────────────────────────────────────────────┘

  NETWORK SEGMENTS
  compute-net   10.10.1.0/24   east-west node traffic     (internal: true)
  storage-net   10.10.2.0/24   shared storage traffic     (internal: true)
  mgmt-net      10.10.3.0/24   control plane + monitoring (internal: true)
  host-access   bridge         dashboard port only        (non-internal)
```

---

## 3. Service Map

| Container | Zone | IP (mgmt-net) | Key Privileges |
|---|---|---|---|
| `docker-socket-proxy` | Infrastructure | 10.10.3.5 | Mounts docker.sock read-only; proxies allowlisted endpoints only |
| `controller` | Infrastructure | 10.10.3.10 | `HMAC_SECRET`, config volume read-only |
| `risk-engine` | Infrastructure | 10.10.3.11 | `NET_ADMIN` cap, `DOCKER_HOST` → socket proxy |
| `dashboard` | Infrastructure | 10.10.3.20 | `shared_data` read-only; port 5000 |
| `aos-frontend` | Infrastructure | 10.10.3.30 | Port 3000 |
| `host-observer` | Infrastructure | 10.10.3.12 | `HMAC_SECRET`, `DOCKER_HOST` → socket proxy |
| `alert_ingestor` | Infrastructure | 10.10.3.40 | UDP :5514 |
| `security-monitor` | Infrastructure | 10.10.3.250 | `NET_ADMIN`, `NET_RAW`, `privileged`, all three networks |
| `node1–node4` | Workload | 10.10.3.21–31 | No caps, no secrets, UID 10001 |

### Docker Socket Proxy — Allowed Endpoints

| API | Consumers |
|---|---|
| `GET /containers/*` | host-observer, security-monitor, risk-engine |
| `GET /events` | security-monitor |
| `GET /images/*` | host-observer |
| `GET /networks/*` | risk-engine |
| `POST /containers/*/pause` | risk-engine |
| `POST /containers/*/stop` | risk-engine |
| `POST /networks/*/disconnect` | risk-engine |
| All other endpoints | ❌ blocked |

---

## 4. Component Reference

### Node Agent (`node_agent/`)

Runs on each workload node as a **simulated tenant workload** — it has no HMAC secret and no visibility into the security infrastructure. Its role in the demo is to generate realistic CPU, memory, and process events that the Host Observer collects externally.

**Key file:** `node_agent/agent.py`

The node agent contains a built-in **attack simulator** that triggers randomly (8% chance per cycle on node1, 3% on others) and escalates through five stages to generate observable signals for the security stack:

| Stage | Actions |
|---|---|
| 1 | CPU spike to 92.5% |
| 2 | Memory spike to 88% + append to `/etc/hosts` |
| 3 | Process count explosion (310) + failed login burst + `chmod 0777 /etc/passwd` |
| 4 | Delete `/etc/ssh/sshd_config` + simulate `hydra` process |
| 5 | Privilege escalation attempt counter |

---

### Shared Secure Messenger (`shared/secure_messenger.py`)

The canonical `SecureMessenger` implementation shared across all Infrastructure Zone services. Handles HMAC-SHA256 signing of every outgoing ZMQ message.

**Key behaviours:**
- Secret resolution order: `HMAC_SECRET` env var → `/run/secrets/hmac_secret` Docker secrets file → ephemeral fallback (causes all messages to be rejected — logs CRITICAL)
- Sequence counter seeded from `time.time() * 1000` to survive container restarts without triggering the controller's replay guard
- `machine_id` resolved from `/etc/machine-id` → `/tmp/node_uuid` (generated UUID)
- `verify_message()` uses `hmac.compare_digest` to prevent timing attacks

Copied into `node_agent/` and `controller/` for import convenience. Canonical source is `shared/secure_messenger.py`.

---

### Controller (`controller/`)

The first line of defence. Every message from every source passes through six sequential checks before being forwarded to the risk engine.

**Key files:**

| File | Description |
|---|---|
| `controller/controller.py` | Main loop; all six security checks; alert factory; offset persistence |
| `controller/entrypoint.sh` | Wrapper that runs `check_config_integrity.py` before starting the controller |

**Six security checks (in order):**

| # | Check | On violation |
|---|---|---|
| 1 | **HMAC-SHA256 verification** | Drop; forward `TELEMETRY_TAMPER` alert |
| 2 | **Rogue node detection** | Drop; forward `ROGUE_NODE` alert |
| 3 | **Replay attack guard** | Drop; forward `REPLAY_ATTACK` alert (checks timestamp freshness, seq monotonicity, duplicate `msg_id` in sliding window) |
| 4 | **Message flooding detection** | Forward `FLOOD_ATTACK` alert; still process original message |
| 5 | **Node impersonation** | Forward `NODE_IMPERSONATION` alert; update tracked `machine_id` |
| 6 | **Duplicate node ID** | Covered by check 5 |

Supporting classes in `controller.py`:
- `ReplayGuard` — per-node deque; evicts entries older than `max_age_seconds`; checks timestamp freshness, seq monotonicity, duplicate `msg_id`
- `FloodGuard` — per-node sliding deque; counts messages per 60 s window

**Offset persistence:** writes a monotonically increasing `_offset` to `/data/controller.offset` (atomic write via temp-file + `os.replace`). The risk engine skips any event with offset ≤ its last committed value.

---

### Host Observer (`host_observer/`)

An Infrastructure Zone service that monitors tenant containers **externally** via the Docker API. No commands are executed inside workload containers.

**Key file:** `host_observer/cluster_observer.py`

**Four detection subsystems:**

#### 1. Resource Telemetry
Reads CPU and memory stats via `container.stats(stream=False)`. Sends `NORMAL` telemetry events every 5 s. CPU/memory percentages are calculated from raw Docker stats (delta CPU time / system time × CPU count).

#### 2. Image Attestation
Compares the running container's image digest (via Docker inspect + `img.attrs["RepoDigests"]`) against `approved_images.yaml`. Generates `IMAGE_MISMATCH` or `UNAPPROVED_IMAGE` events with full digest evidence. Includes a 60-second grace period for newly started containers.

#### 3. Runtime Drift Detection
Extracts live container config via Docker inspect: user, `CapAdd`/`CapDrop`, bind mounts, attached networks, restart policy, security options, image digest. Compares field-by-field against `runtime_baseline.yaml`. Generates `RUNTIME_DRIFT` events with a per-field diff showing expected vs actual values.

#### 4. Infrastructure Config Integrity (`InfraConfigGuard`)
Monitors SHA-256 hashes of the five infrastructure-owned YAML config files. Anchored to `config_hashes.yaml` (generated from a known-good state), **not** a startup snapshot. Checks every 30 s. Generates `POLICY_TAMPER`, `ALLOWLIST_TAMPER`, or `CONFIG_DRIFT` events. Only monitors security infrastructure files — never customer data.

---

### Security Monitor (`security_monitor/`)

An Infrastructure Zone service that runs a five-stage Python pipeline alongside Suricata (NIDS) and a Zeek emulator for passive network monitoring. Has `NET_ADMIN`, `NET_RAW`, and `privileged` capabilities; attached to all three network segments.

**Key files:**

| File | Role |
|---|---|
| `main.py` | Supervisor; launches Suricata and Zeek emulator as subprocesses; starts all pipeline threads |
| `docker_collector.py` | Subscribes to Docker event stream; detects exec events, restart loops, network attaches, renames |
| `falco_collector.py` | Tails `/var/log/falco/events.json`; classifies Falco rules into `REVERSE_SHELL`, `CONTAINER_ESCAPE_ATTEMPT`, `PRIV_ESC_ATTEMPT`, `FALCO_ALERT` |
| `network_collector.py` | Tails Suricata `eve.json` and Zeek `notice.log`; emits `NETWORK_THREAT` and behavioural notices |
| `threat_correlator.py` | Joins network alerts with Docker events within a 10-second window; escalates severity to CRITICAL on correlation |
| `policy_engine.py` | Evaluates correlated events against `fast_path_policy.yaml`; applies immediate Docker actions (stop, pause, network-isolate) before scoring |
| `event_forwarder.py` | HMAC-signs events as `security-monitor` and pushes to controller via ZMQ PUSH; token-bucket rate limiter (15 msg/60 s) prevents triggering the controller's flood guard |

**Falco integration:** Falco runs natively on the host (`falco --modern-bpf`) and writes JSON events to `/var/log/falco/events.json`. The `security-monitor` container mounts this path read-only and `falco_collector.py` tails it. No containerised Falco process is required.

**Suricata rules** are defined in `security_monitor/suricata/hpc-scan.rules` and `suricata.yaml`. Zeek behavioural logic is in `security_monitor/zeek/hpc_monitor.zeek` with a Python emulator (`zeek_emulator.py`).

---

### Risk Engine (`risk_engine/`)

The central processing engine. Receives validated telemetry over ZMQ PULL, runs a multi-stage scoring pipeline, drives enforcement, and persists everything to SQLite.

**Key files:**

| File | Class / Description |
|---|---|
| `engine.py` | Entry point; ZMQ PULL listener; pipeline orchestration; heartbeat checker thread; routes controller-injected security alerts |
| `pipeline.py` | `Pipeline` + `Decision` dataclass; enrichment → correlation → rule matching → scoring in sequence |
| `enrichment.py` | `Enricher`; pulls cumulative score and 7-day incident count from SQLite |
| `correlation.py` | `Correlator`; two modes: cross-node (same rule, ≥ 3 nodes, 600 s window → 1.5× multiplier) and multi-signal (specific threat combinations on the same node) |
| `rules.py` | `RuleEngine`; loads `rules.yaml`; matches rules against event `reasons` string; hot-reloads on file change via `watchdog` |
| `scoring.py` | `WeightedScorer`; `event_score = severity × blast_radius × asset_criticality / 1000 × multiplier`; decay on clean events; 5-min decay hold after FIM/security events |
| `router.py` | `Router`; dispatches bucket actions; captures pre-quarantine forensics; sends Wazuh/alert-ingestor UDP syslog |
| `network_isolator.py` | `NetworkIsolator`; pause, unpause, stop, Docker network disconnect, and iptables FORWARD DROP (with IP validation to prevent injection) |
| `threat_detector.py` | `ThreatDetector`; secondary per-event detectors: rogue node, impersonation, secondary flood, lateral movement, config tampering, unauthorized process; builds `SILENT_NODE` signals |
| `alert_manager.py` | `AlertManager` + `SecurityAlert` + `ThreatSignal` dataclasses; converts signals to alerts; persists to `security_alerts` table; logs at appropriate level |
| `remediation_engine.py` | `RemediationEngine`; loads `remediations.yaml` playbooks; executes bash scripts via Docker `exec_run`; logs results to the `events` table as `AUTO_REMEDIATION` events |
| `cmd_server.py` | ZMQ REP server on `:5557`; receives human-review commands from the dashboard (`approve`, `deny`, `restart`, `reset`, `simulate`); manages iptables rules and container lifecycle |
| `simulator.py` | Programmatic attack simulator; 11 attack types dispatched by `cmd_server`; uses Docker SDK, ZMQ PUSH, or direct DB injection depending on attack type |
| `store.py` | `Store`; all SQLite read/write; schema init + migrations; WAL mode |

**Processing pipeline (per event):**

```
ZMQ recv → validate → skip if offset ≤ last_committed
    │
    ├─ security_alert=True ──► AlertManager.emit_from_event()
    │
    └─ standard telemetry:
        1. Enricher.enrich()              — current_score, incident_count_7d
        2. RuleEngine.match()             — list of (rule_id, severity, blast_radius)
        3. Correlator.check()             — correlated flag + multiplier
        4. WeightedScorer.score()         — event_score, cumulative_score, bucket
        5. Store.write_event()            — persist to events table
        6. Store.update_node_status()     — update node_status table
        7. Router.dispatch()              — pre-quarantine forensics + enforcement + syslog
        8. ThreatDetector.run()           — secondary threat checks
        9. AlertManager.emit_batch()      — persist new security alerts
       10. RemediationEngine.process_alert() — trigger playbook if applicable
```

**Heartbeat checker:** background thread; checks every 10 s; emits `SILENT_NODE` alert via `AlertManager` and writes `NODE_UNRESPONSIVE` event for any node silent beyond its configured timeout.

---

### Dashboard (`dashboard/`)

Two-layer dashboard: a Flask REST API (`app.py`, port 5000) serving SQLite data, and a Next.js frontend (`aos-dashboard/`, port 3000).

**Key files:**

| File | Description |
|---|---|
| `dashboard/app.py` | Flask API; security headers middleware; all REST endpoints; parameterised queries only |
| `dashboard/incident_summary.py` | LLM-free incident narrative generator; MITRE ATT&CK + NIST SP 800-234 mappings; multi-signal correlation labels; risk trajectory; recommended action logic |
| `dashboard/templates/index.html` | Legacy single-page dashboard (Flask server-rendered); XSS-safe DOM helpers |
| `dashboard/aos-dashboard/` | Next.js + TypeScript frontend; components, hooks, services, types |

**Flask API endpoints:**

| Route | Description |
|---|---|
| `GET /` | Legacy server-rendered dashboard HTML |
| `GET /api/nodes` | All rows from `node_status` |
| `GET /api/nodes/identity` | Node identity registry (machine_id, trust, first/last seen) |
| `GET /api/nodes/security` | Joined per-node security summary: status, risk, replay, flood, tamper, lateral movement counts |
| `GET /api/alerts` | Paginated security alerts; filters: `limit`, `severity`, `node_id`, `threat_type` (severity allowlist-validated) |
| `GET /api/alerts/stats` | Aggregate: total, by type, by severity, last 24h, replay total |
| `GET /api/forensics/<node>` | Latest forensic snapshot for a node |
| `GET /api/incident-summary/<node>` | Full structured incident summary from `incident_summary.py` (MITRE, NIST, narrative, timeline, correlations) |
| `POST /api/cmd` | Proxies human-review commands to risk engine ZMQ REP server |

**`incident_summary.py`** generates:
- Plain-English 4-sentence narrative (no LLM required)
- MITRE ATT&CK technique mapping for every observed threat type
- NIST SP 800-234 control references
- Multi-signal correlation pattern detection
- Risk score trajectory (sparkline data)
- Confidence level (LOW / MEDIUM / HIGH)
- Recommended action (QUARANTINE / INVESTIGATE_FURTHER / APPROVE_AND_RESUME)

---

### Alert Ingestor (`alert_ingestor/`)

A lightweight mock SIEM. Listens on UDP port 5514 and receives JSON syslog payloads from the risk engine's `Router`. Persists alerts to the `alert_ingestor_alerts` SQLite table. Replaces the earlier Wazuh mock (which used port 514).

**Key file:** `alert_ingestor/alert_ingestor.py`
Custom Suricata rules for HPC environments: `alert_ingestor/rules/hpc_network_rules.xml`

---

## 5. Detection Coverage

All threat types, their source, and default severity:

| Threat Type | Source | Severity | Description |
|---|---|---|---|
| `TELEMETRY_TAMPER` | Controller | HIGH | HMAC signature invalid |
| `ROGUE_NODE` | Controller + ThreatDetector | CRITICAL | Node name not in allowlist |
| `REPLAY_ATTACK` | Controller | HIGH | Stale timestamp, non-monotonic seq, or duplicate `msg_id` |
| `FLOOD_ATTACK` | Controller + ThreatDetector | MEDIUM | > `max_msgs_per_60s` messages in 60 s window |
| `NODE_IMPERSONATION` | Controller + ThreatDetector | CRITICAL | Node's `machine_id` changed between messages |
| `DUPLICATE_NODE_ID` | Controller (impersonation logic) | HIGH | Two sources using the same node name |
| `SILENT_NODE` | Risk Engine heartbeat thread | HIGH | Node stopped reporting for longer than configured timeout |
| `LATERAL_MOVEMENT` | ThreatDetector | HIGH | Unexpected SSH connections to peer IPs |
| `UNAUTH_PROCESS` | ThreatDetector | MEDIUM | Process on denylist (or not on allowlist) |
| `IMAGE_MISMATCH` | Host Observer | HIGH | Running image digest differs from `approved_images.yaml` |
| `UNAPPROVED_IMAGE` | Host Observer | MEDIUM | No approved digest exists for this node |
| `RUNTIME_DRIFT` | Host Observer | HIGH | Cap, volume, network, user, or security option drift vs `runtime_baseline.yaml` |
| `CONFIG_DRIFT` | Host Observer | MEDIUM | Infrastructure config file hash changed (generic) |
| `POLICY_TAMPER` | Host Observer | CRITICAL | `rules.yaml` or `fast_path_policy.yaml` modified |
| `ALLOWLIST_TAMPER` | Host Observer | CRITICAL | `master_config.yaml` modified |
| `CONTAINER_EXEC` | Security Monitor (docker_collector) | HIGH | `exec_create` on a workload container |
| `UNEXPECTED_EXEC` | Security Monitor (docker_collector) | HIGH | `exec_start` on a workload container |
| `SUSPICIOUS_RESTART_PATTERN` | Security Monitor (docker_collector) | MEDIUM | ≥ 5 restarts within 120 s |
| `UNEXPECTED_NETWORK_ATTACH` | Security Monitor (docker_collector) | HIGH | Container connected to a network it shouldn't be on |
| `CONTAINER_RENAME` | Security Monitor (docker_collector) | MEDIUM | Container identity manipulation |
| `NETWORK_THREAT` | Security Monitor (network_collector / Suricata) | MEDIUM–CRITICAL | Suricata signature match |
| `FALCO_ALERT` | Security Monitor (falco_collector) | MEDIUM | Generic Falco rule match |
| `REVERSE_SHELL` | Security Monitor (falco_collector) | CRITICAL | Falco reverse shell rule |
| `PRIV_ESC_ATTEMPT` | Security Monitor (falco_collector) | CRITICAL | Falco privilege escalation rule |
| `CONTAINER_ESCAPE_ATTEMPT` | Security Monitor (falco_collector) | CRITICAL | Falco container escape rule |

---

## 6. Risk Scoring & Enforcement

### Scoring formula

```
event_score = max(severity × blast_radius × asset_criticality / 1000) × correlation_multiplier
cumulative_score += event_score
```

- **severity** and **blast_radius** come from the matched rule in `rules.yaml`
- **asset_criticality** is a per-node weight from `master_config.yaml` (range 0–30; node4 = 20, others = 3–5)
- **correlation_multiplier** is up to 3.0× for multi-signal correlations
- On events with no rule matches, the score **decays** by `decay_rate` (default 5.0 per cycle)
- Security events (FIM, tamper, etc.) suppress decay for 5 minutes

### Buckets (`master_config.yaml`)

| Bucket | Score range | Enforcement action |
|---|---|---|
| `info` | 0–20 | Log only |
| `low` | 21–40 | Log only |
| `medium` / `auto` | 41–70 | Wazuh/alert-ingestor WARNING + auto-remediation |
| `high` / `human` | 71–100 | Docker pause + alert-ingestor HIGH + human review queue |
| `critical` / `quarantine` | > 100 | Pre-quarantine forensic capture + Docker stop + iptables DROP + alert-ingestor CRITICAL |

### Router enforcement actions (`risk_engine/router.py`)

- **`auto`** bucket → send UDP syslog alert (WARNING)
- **`human`** bucket → `NetworkIsolator.pause_node()` + UDP syslog (HIGH) + update status to `awaiting_approval`
- **`quarantine`** bucket → `_capture_forensics()` first, then `NetworkIsolator.stop_node()` + `NetworkIsolator.quarantine_network()` (iptables FORWARD DROP for all node IPs) + UDP syslog (CRITICAL)

### Rules (`risk_engine/config/rules.yaml`)

| Rule ID | Matches `reasons` | Severity | Blast Radius |
|---|---|---|---|
| `HIGH_CPU` | "CPU" | 10 | 5 |
| `HIGH_MEMORY` | "memory" | 10 | 5 |
| `PROCESS_COUNT` | "Too many" | 15 | 10 |
| `SUSPICIOUS_PROCESS` | "Suspicious process" | 35 | 20 |
| `ROGUE_NODE` | "Rogue node" | 50 | 30 |
| `NODE_IMPERSONATION` | "machine_id" | 60 | 40 |
| `REPLAY_ATTACK` | "Replay attack" | 45 | 25 |
| `FLOOD_ATTACK` | "flooding" | 30 | 15 |
| `LATERAL_MOVEMENT` | "Lateral movement" | 55 | 35 |
| `CONFIG_TAMPER` | "Config tamper" | 50 | 30 |
| `UNAUTH_PROCESS` | "Unauthorized process" | 35 | 20 |
| `SILENT_NODE` | "not reported" | 40 | 20 |
| `TELEMETRY_TAMPER` | "HMAC" | 50 | 30 |
| `IMAGE_MISMATCH` | "Image digest mismatch" | 65 | 40 |
| `RUNTIME_DRIFT` | "Runtime drift" | 60 | 40 |
| `POLICY_TAMPER` | "Infrastructure config modified" | 65 | 45 |
| `CONTAINER_EXEC` | "exec_start" | 45 | 25 |
| `FALCO_ALERT` | "Falco" | 50 | 30 |
| `REVERSE_SHELL` | "Reverse shell" | 80 | 60 |
| `CONTAINER_ESCAPE` | "Container escape" | 90 | 70 |

Rules are hot-reloaded via `watchdog` — no restart required after editing `rules.yaml`.

---

## 7. Multi-Signal Correlation

The `Correlator` in `risk_engine/correlation.py` runs two independent correlation modes simultaneously:

**Cross-node correlation:** the same rule ID fires on ≥ 3 distinct nodes within 600 s → 1.5× score multiplier on subsequent events.

**Multi-signal correlation:** specific combinations of threat types on the same node within a time window trigger elevated confidence findings:

| Combination | Window | Multiplier | Label |
|---|---|---|---|
| `REVERSE_SHELL` + `NETWORK_THREAT` | 120 s | 2.5× | High Confidence Compromise |
| `FALCO_ALERT` + `RUNTIME_DRIFT` + `NETWORK_THREAT` | 300 s | 3.0× | Critical Multi-Signal Risk |
| `CONTAINER_EXEC` + `PRIV_ESC_ATTEMPT` | 180 s | 2.5× | Active Attack Chain |
| `IMAGE_MISMATCH` + `RUNTIME_DRIFT` | 600 s | 2.0× | Deployment Tamper |
| `ALLOWLIST_TAMPER` + `ROGUE_NODE` | 600 s | 3.0× | Coordinated Intrusion |
| `CONTAINER_ESCAPE_ATTEMPT` + `PRIV_ESC_ATTEMPT` | 120 s | 3.0× | Container Escape |

The `security_monitor/threat_correlator.py` performs a separate **real-time** correlation by joining network/Falco alerts with Docker events that occurred on the same node within a 10-second window, escalating severity to CRITICAL on a match.

---

## 8. Fast-Path Policy Engine

`security_monitor/policy_engine.py` evaluates events **before** they reach the risk engine's scoring pipeline. Rules are defined in `risk_engine/config/fast_path_policy.yaml` and matched by `threat_type` and/or `severity`.

Fast-path actions bypass cumulative scoring entirely:

| Trigger | Action |
|---|---|
| `ROGUE_NODE` | quarantine (Docker stop) |
| `TELEMETRY_TAMPER` | quarantine |
| `POLICY_TAMPER` (CRITICAL) | quarantine |
| Any `CRITICAL` severity | quarantine |
| `LATERAL_MOVEMENT` | pause |
| `Fanout_Excess` | network_isolate (disconnect from compute-net + storage-net) |
| `REVERSE_SHELL` | quarantine |
| `CONTAINER_ESCAPE_ATTEMPT` | quarantine |
| `PRIV_ESC_ATTEMPT` | pause |

Every action is logged to `/var/log/security/audit.log`.

---

## 9. Auto-Remediation Playbooks

### Auto-Remediation Tracks (Playbooks)

The system automatically triggers bash-based remediation scripts when a node's cumulative risk score enters the **Medium** (`auto`) bucket (score 41–70) or when specifically mandated by a correlated threat profile. These playbooks are executed by the Risk Engine strictly in the Infrastructure Zone.

**Crucial Security Invariant:** No auto-remediation playbook ever executes arbitrary code, modifies internal tenant data files, or kills processes *inside* a tenant workload container. All enforcement is executed at the outer host abstraction layer.

**Execution Supersedence:** If a container is already paused or quarantined by a primary security policy (e.g. cumulative score reaching Critical/High) before a playbook executes, the engine safely supersedes the playbook and logs a clean `Execution superseded` event instead of crashing with Docker 409 API errors.

### 1. Isolate Data Networks (`RUNTIME_DRIFT`)
* **Purpose:** To neutralize unauthorized container configurations (like unexpected network attachments or security opt changes) that bypass normal container startup.
* **Trigger:** The `host-observer` detects drift in the container's runtime baseline (e.g., unexpected network connections or capability changes).
* **Action Details:** 
  1. The playbook extracts the exact drifted configuration fields from the alert evidence.
  2. It leverages the Docker SDK via the `NetworkIsolator` to physically disconnect the compromised container from all data-plane networks (`compute-net` and `storage-net`).
  3. The management network remains connected solely to allow security teams to safely shell into the isolated environment for forensics.
* **Impact:** The container is instantly severed from sensitive data networks without relying on unreliable in-container process killing, neutralizing the threat while preserving forensic state.

### 2. Isolate Rogue Network Segment (`UNEXPECTED_NETWORK_ATTACH`)
* **Purpose:** To prevent lateral movement and unauthorized exfiltration when a container attempts to join a network it doesn't belong to.
* **Trigger:** The `security-monitor` detects a workload container maliciously attaching to an unauthorized subnet.
* **Action Details:**
  1. The playbook triggers a dual host-level enforcement action bypassing the container completely.
  2. First, it uses the Docker SDK to immediately disconnect the container from all data networks.
  3. Second, it applies an `iptables FORWARD DROP` rule directly on the host machine's bridge network for the container's IP.
* **Impact:** The container's network access is physically severed. Even if the container attempts to reconnect to the network internally, the host-level firewall rules drop the traffic instantly. Legitimate traffic on the management cluster net remains unaffected.

### 3. Restore Configuration Baseline (`CONFIG_DRIFT`)
* **Purpose:** To self-heal the security infrastructure if an attacker attempts to tamper with critical system configuration files.
* **Trigger:** The `host-observer`'s integrity checks detect that the SHA-256 hashes of infrastructure configuration files drifted from the `config_hashes.yaml` baseline.
* **Action Details:**
  1. The playbook is triggered to run on the Infrastructure node.
  2. It locates the secure, read-only backup directory (`/etc/config.bak`).
  3. It executes a clean copy (`cp /etc/config.bak /etc/config`) to overwrite the tampered configuration files.
* **Impact:** Any attacker modification to security rules or scoring weights is instantly reverted.

### 4. Revoke SSH Keys & Reset (`LATERAL_MOVEMENT`)
* **Purpose:** To instantly block attackers who are attempting to spread laterally across nodes using compromised SSH credentials.
* **Trigger:** The `security-monitor` (via Suricata or Zeek) flags anomalous SSH login attempts, or the `host-observer` detects rogue key additions.
* **Action Details:**
  1. The playbook executes `pkill -9 sshd` to forcefully evict any active, unauthorized SSH sessions on the target node.
  2. It triggers a rotation script to regenerate ephemeral SSH keys.
* **Impact:** The lateral traversal pathway is immediately cut off. The attacker loses their session and cannot reconnect using the stolen credentials.

### 5. Verify Container Digest & Restart (`IMAGE_MISMATCH`)
* **Purpose:** To ensure that the running container image perfectly matches the cryptographically signed and approved baseline.
* **Trigger:** The `host-observer` detects that the running container's image digest no longer matches the expected SHA-256 digest in `approved_images.yaml`.
* **Action Details:**
  1. The playbook signals the container runtime to stop the tampered container.
  2. It reaches out to the trusted local container registry to re-pull the verified and approved image manifest.
  3. It restarts the application service, thereby spawning a fresh, pristine container from the verified image.
* **Impact:** The compromised container instance is destroyed and replaced with a clean instance, wiping out any filesystem tampering that occurred outside of persistent volumes.

---

## 10. Attack Simulator

`risk_engine/simulator.py` is callable from the Next.js dashboard via the ZMQ command server (`cmd_server.py`). All 11 attack types are available:

| Attack | Method | Expected alerts |
|---|---|---|
| `docker_exec` | Docker SDK `exec_run("id")` | `CONTAINER_EXEC`, `UNEXPECTED_EXEC` |
| `runtime_drift_network` | Connect node to `storage-net`; auto-disconnect after 30 s | `RUNTIME_DRIFT` (field: networks) |
| `suspicious_restart` | Restart container × 6 with 1.5 s delay | `SUSPICIOUS_RESTART_PATTERN` |
| `image_mismatch` | Inject `IMAGE_MISMATCH` alert via ZMQ | `IMAGE_MISMATCH` |
| `config_tamper` | Inject `POLICY_TAMPER` alert via ZMQ | `POLICY_TAMPER` |
| `allowlist_tamper` | Inject `ALLOWLIST_TAMPER` alert via ZMQ | `ALLOWLIST_TAMPER` |
| `rogue_node` | Send HMAC-signed ZMQ message with a node name not in the allowlist | `ROGUE_NODE` (controller-detected) |
| `replay_attack` | Sign once; send same envelope twice via ZMQ | `REPLAY_ATTACK` (controller-detected) |
| `multi_signal` | `docker_exec` + `runtime_drift_network` with 5 s delay | Correlated `CONTAINER_EXEC` + `RUNTIME_DRIFT` (2.5× multiplier) |
| `image_mismatch_demo` | Direct DB injection with forensic snapshot | `IMAGE_MISMATCH` (demo mode) |
| `multi_signal_demo` | Direct DB injection with forensic snapshot | `MULTI_SIGNAL` (demo mode) |

---

## 11. Configuration Files

All config files are in `risk_engine/config/` and mounted read-only into the controller, risk engine, host observer, and security monitor.

### `master_config.yaml`
Unified config replacing the old `allowlist.yaml`, `thresholds.yaml`, and `node_criticality.yaml`. Contains: `allowed_nodes`, `flood_threshold`, `replay_protection`, `heartbeat_timeout_seconds`, `network_detection`, `node_criticality`, `buckets`, `decay_rate`.

### `rules.yaml`
List of scoring rules. Each entry: `id`, `match.reasons_contains`, `severity`, `blast_radius`. Hot-reloaded by `watchdog`.

### `fast_path_policy.yaml`
Fast-path enforcement rules for `policy_engine.py`. Fields: `threat_type`, `severity`, `action` (`quarantine` / `pause` / `network_isolate`). First-match wins.

### `remediations.yaml`
Playbook definitions for `RemediationEngine`. Each playbook: `name`, `script` (inline bash). Keyed by threat type.

### `approved_images.yaml`
Maps container names to their expected SHA-256 image digests. Populated by `scripts/capture_approved_images.py` after first build.

### `runtime_baseline.yaml`
Maps container names to their expected runtime state: `user`, `cap_add`, `cap_drop`, `binds`, `networks`, `restart_policy`, `security_opts`. Populated by `scripts/capture_runtime_baseline.py`.

---

## 12. Database Schema

All tables live in `/data/events.db` (SQLite, WAL mode). The `Store` class in `risk_engine/store.py` owns schema creation and migrations. The shared data volume is mounted read-only into the dashboard.

| Table | Purpose |
|---|---|
| `events` | Every processed telemetry event: timestamps, node, CPU/memory/process, FIM details, risk score, bucket, matched rules, correlated flag |
| `node_scores` | Latest cumulative risk score per node |
| `node_status` | Latest operational status per node: `idle`, `busy`, `awaiting_approval`, `quarantined`, `unresponsive`; `isolated_ip` for iptables tracking |
| `engine_offset` | Single-row table; last committed message offset |
| `security_alerts` | All threat alerts: UUID, timestamp, node_id, severity, threat_type, description, JSON evidence, recommended action. Indexed on `(node_id, timestamp)` and `(severity, timestamp)` |
| `node_identity` | Per-node identity: machine_id, first_seen, last_seen, trust_status (`TRUSTED` / `SUSPECT` / `ROGUE` / `UNKNOWN`) |
| `replay_log` | Every detected replay attempt: node, msg_id, seq, detected_at |
| `forensic_snapshots` | Pre-quarantine evidence captures: processes, network_conns, container_state, recent alerts, artifact_path |
| `review_decisions` | Human review outcomes: node, decision (`approve` / `deny`), notes, timestamp |
| `integrity_audits` | Written to `/data/integrity_audits/` as JSON files by `check_config_integrity.py` |
| `alert_ingestor_alerts` | Alerts received by the alert ingestor UDP listener |

---

## 13. Build-Time Security Pipeline

Two GitHub Actions workflows run on every push and pull request to `main`.

### `.github/workflows/build-time-security.yml`

```
Push / PR
    │
    ├── Stage 1 — Blocking, serial
    │   ├── secret-detection    GitLeaks v8.30.1 full history scan
    │   └── yaml-validation     yamllint + PyYAML safe_load on all configs
    │
    ├── Stage 2 — Blocking, parallel (after Stage 1)
    │   ├── sast-bandit         Python SAST; blocks on HIGH severity; uploads SARIF
    │   ├── sast-semgrep        p/python + p/secrets + p/owasp-top-ten; uploads SARIF
    │   └── sca-pip-audit       CVE scan on dashboard/ and node_agent/ requirements
    │
    ├── Stage 3 — Advisory, parallel (after Stage 1)
    │   ├── shellcheck          Shell script linting (SC-WARNING, advisory only)
    │   ├── hadolint            Dockerfile best-practice lint (advisory only)
    │   ├── checkov             docker-compose.yml IaC scan; uploads SARIF
    │   └── trivy               Filesystem CVE scan; blocks on CRITICAL; uploads SARIF
    │
    └── security-gate           Final pass/fail; evaluates 6 blocking jobs
```

Blocking jobs: `secret-detection`, `yaml-validation`, `sast-bandit`, `sast-semgrep`, `sca-pip-audit`, `trivy`.
Advisory jobs: `shellcheck`, `hadolint`, `checkov`.

### `.github/workflows/sbom.yml`
Generates a Software Bill of Materials using Syft on every merge to `main`.

### Pre-flight Config Integrity Check (`scripts/check_config_integrity.py`)

Enforces NIST CM-2 / CM-6 / SI-7. Called automatically from `controller/entrypoint.sh` and `risk_engine/entrypoint.sh` before service startup. Verifies SHA-256 hashes of `rules.yaml` and `master_config.yaml` against `config_hashes.yaml`.

- **Exit 0** → all verified, service starts
- **Exit 1** → manifest missing (service blocked)
- **Exit 2** → one or more files tampered (service blocked)
- **Exit 3** → unexpected error (service blocked)

Writes machine-readable JSON audit records to `/data/integrity_audits/`.

---

## 14. Deployment

### Prerequisites

Docker, Docker Compose, Python 3.11.

```bash
# Ubuntu / Debian
sudo apt install docker.io docker-compose-plugin python3-venv python3-pip -y

# Arch
sudo pacman -S docker docker-compose python
```

### Quick Start (automated)

```bash
git clone <repository-url>
cd Always-On-Security
cp .env.example .env          # set HMAC_SECRET to a 64-char hex string

chmod +x build_and_start.sh
./build_and_start.sh
```

`build_and_start.sh` automatically:
1. Builds and starts all containers in detached mode
2. Waits for `node1`–`node4` to initialise (60 s grace)
3. Captures image digests → `risk_engine/config/approved_images.yaml`
4. Captures runtime baseline → `risk_engine/config/runtime_baseline.yaml`
5. Restarts `host-observer` so it loads the updated baselines
6. Streams all logs to the foreground

### Manual Start

```bash
docker compose up --build -d

# Capture baselines after nodes are running
python3 -m venv .venv && source .venv/bin/activate
pip install -r host_observer/requirements.txt
python3 scripts/capture_approved_images.py
python3 scripts/capture_runtime_baseline.py

docker compose restart host-observer
docker compose logs -f
```

### Access

| Service | URL |
|---|---|
| Next.js dashboard | http://localhost:3000 |
| Flask API | http://localhost:5000 |

### Useful commands

```bash
docker compose logs -f risk-engine
docker compose logs -f host-observer
docker compose logs -f security-monitor
docker compose down -v        # stop and remove shared_data volume
```

---

## 15. Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `HMAC_SECRET` | **Yes** | — | Shared HMAC-SHA256 secret. Must be identical on controller, risk-engine, host-observer, and security-monitor. Generate: `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `NODE_NAME` | node agent | `hostname` | Node identifier; must match an entry in `master_config.yaml` |
| `ALLOWLIST_PATH` | controller, risk-engine, host-observer | `/opt/security/config/master_config.yaml` | Path to master config |
| `CONTROLLER_URL` | host-observer, security-monitor | `tcp://controller:5555` | ZMQ endpoint of the controller |
| `DOCKER_HOST` | risk-engine, host-observer, security-monitor | `tcp://docker-socket-proxy:2375` | Routes Docker SDK calls through the socket proxy |
| `SURICATA_INTERFACE` | security-monitor | `eth0` | Network interface for Suricata |
| `ZEEK_INTERFACE` | security-monitor | `eth0` | Network interface for Zeek |
| `FALCO_OUTPUT_FILE` | security-monitor | `/var/log/falco/events.json` | Path to Falco JSON output log |
| `INTEGRITY_STRICT` | controller, risk-engine | `false` | If `true`, config files with no manifest entry block startup |
| `INTEGRITY_ALLOW_MISSING_MANIFEST` | controller, risk-engine | `false` | If `true`, a missing `config_hashes.yaml` is a warning only (for initial deployment) |
| `CONFIG_HASHES_PATH` | scripts | `/opt/security/config/config_hashes.yaml` | Path to the SHA-256 hash manifest used by the pre-flight check |

---

## Supporting Scripts (`scripts/`)

| Script | Purpose |
|---|---|
| `capture_approved_images.py` | Reads running image digests via Docker API; writes `risk_engine/config/approved_images.yaml` |
| `capture_runtime_baseline.py` | Reads live container inspect data; writes `risk_engine/config/runtime_baseline.yaml` |
| `check_config_integrity.py` | Pre-flight integrity check (NIST SI-7); called by `entrypoint.sh` on controller and risk-engine |
| `compute_baseline.py` | Computes SHA-256 hashes of config files; updates `config_hashes.yaml` |
| `beaconing_detector.py` | Offline analysis script for detecting periodic outbound connection patterns in network logs |
| `enforce_segment_iptables.sh` | Host-level iptables enforcement for network segment isolation |
| `entrypoint.sh` | Shared entrypoint wrapper used by scripts that need pre-flight checks |

`generate_baseline.py` (project root) generates `config_hashes.yaml` from a known-good node state:

```bash
python3 generate_baseline.py
# or with custom files:
python3 generate_baseline.py --files /etc/hosts,/etc/passwd --out ./risk_engine/config/config_hashes.yaml
```
