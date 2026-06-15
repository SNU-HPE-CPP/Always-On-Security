# Always-On-Security

A distributed, container-based security monitoring simulation that demonstrates real-time anomaly detection, cumulative risk scoring, automated quarantine, and live dashboard visualization.

*Note: This project has been significantly enhanced with an **Advanced Security Layer** providing cryptographic node identity, replay protection, and node-level threat detection.*

---

## Architecture Overview

The system is built as a multi-container Docker application with the following layers:

1. **Layer 1: Node Agents (`node_agent/`)** — Dual-threaded edge agents that collect system telemetry (CPU, memory, process count) while simulating workload states. Includes a built-in threat simulator for testing.
2. **Layer 2: Event Bus & Durability (`controller/`)** — A lightweight message forwarder that receives telemetry via ZeroMQ, stamps events with a sequential offset, and persists state atomically for crash recovery.
3. **Layer 3: Risk Engine (`risk_engine/`)** — A stateless Python microservice that assesses risk. Features context-aware threshold checks, risk decay (self-healing), cross-node correlation, heartbeat monitoring, and node-side network threat alerts.
4. **Layer 4: Auto-Remediation (`risk_engine/router.py`)** — Monitors risk levels and routes decisions into buckets (silent, auto, human, quarantine). Initiates container-based node isolation via the Docker API.
5. **Layer 5: Visibility & Alerting (`dashboard/`, `wazuh/`, `security_monitor/`)** — A Flask-based web dashboard, a mock Wazuh SIEM manager, and a dedicated security monitor container running Suricata + Zeek on the Docker segments.

```
                ┌──────────────────────────────────┐
                │          RISK ENGINE             │
                │  YAML Rules & Scoring Pipeline   │
                │  Heartbeat & Correlation         │
                │  Remediation Router              │──► Docker API (Quarantine)
                │  DB Writer                       │──► SQLite
                └───────────────▲──────────────────┘
                                │ ZMQ :5556
                ┌───────────────┴──────────────────┐
                │          CONTROLLER              │
                │  Message Forwarder & Offsets     │
                └───────────────▲──────────────────┘
                                │ ZMQ :5555
                ┌───────────────┴──────────────────┐
                │          NODE AGENTS             │  ×4 (compute and storage nodes)
                │  Telemetry & Threat Simulator    │
                └──────────────────────────────────┘

                ┌───────────────┐  ┌───────────────┐
                │   DASHBOARD   │  │     WAZUH     │
                │ localhost:5000│  │ Mock SIEM :514│
                └───────────────┘  └───────────────┘

                ┌──────────────────────────────────┐
                │ SECURITY MONITOR                 │
                │ Suricata + Zeek + Filebeat       │
                │ compute-net / storage-net / mgmt │
                └──────────────────────────────────┘
```

---

## Key Features

* **Cumulative Risk Scoring & Self-Healing:** The controller maintains a cumulative risk score for each node. If anomalies cease, the risk score decays slowly back to 0. Accounts for asset criticality.
* **Heartbeat Monitor:** Detects silent node failures. If a node fails to send telemetry for 30 seconds, it is marked as unresponsive.
* **Cross-Node Correlation:** Detects coordinated attacks hitting 3+ nodes simultaneously and applies a risk multiplier.
* **Automated Quarantine:** Once a node's cumulative risk score hits or exceeds `100` (quarantine bucket), the system automatically stops the compromised node's container via the Docker API.
* **Mock Wazuh Integration:** A simulated Wazuh SIEM manager receives and displays security alerts via UDP when a node is quarantined.

---

## Security Detection Rules

| Rule | Trigger Condition | Risk Increment |
| :--- | :--- | :--- |
| **High CPU** | CPU > 10% | `+20` risk points |
| **High Memory** | Memory > 50% | `+20` risk points |
| **Too Many Processes** | Process count > 300 | `+25` risk points |
| **Suspicious Process** | Binary name match (e.g. `nmap`, `hydra`, `nc`, `stress`) | `+40` risk points |
| **Network Threat** | Suspicious TCP egress, unexpected listeners, or high fan-out | `+55` risk points |

---

## Suspicious Activity Detection

Currently, a node is marked as suspicious if it exhibits one or more of the following:

* High CPU usage
* High memory usage
* Excessive number of running processes
* Suspicious process names (e.g., `stress`, `nmap`, `hydra`, `netcat`)

**Additionally, the system now covers advanced Node-Related Threats:**
* **Rogue Node Detection**: Rejects telemetry from unauthorized machine IDs.
* **Replay Attacks**: Blocks duplicated, previously seen messages.
* **Message Flooding**: Rate limits excessive telemetry from a single node.
* **Config Tampering**: Hashes critical files (e.g. `/etc/hosts`) against a baseline.
* **Lateral Movement**: Detects unexpected outbound SSH connections.
* **Network Threat Detection**: Flags suspicious TCP egress, unexpected listening ports, and fan-out spikes that do not fit the cluster network profile.
* **Telemetry Tampering**: Validates cryptographic HMAC-SHA256 signatures on all messages.

## Network Simulation

The Docker topology is split into three isolated segments:

* `compute-net` for MPI-like east-west communication
* `storage-net` for shared storage access
* `mgmt-net` for control-plane and monitoring traffic

The `security-monitor` container is attached to all three segments and is intended to inspect the Docker bridge/veth interfaces directly. Suricata handles scan and protocol-abuse detections, while Zeek handles whitelist violations, connection-graph tracking, and baseline deviation notices. Filebeat is configured to ship the generated logs into the SIEM pipeline.

### Baseline and Detection Artifacts

* `scripts/compute_baseline.py` reads Zeek conn logs and writes `baselines/baseline.json`
* `scripts/beaconing_detector.py` reads conn logs and emits beaconing alerts to JSON
* `scripts/enforce_segment_iptables.sh` applies host-side segment boundaries with iptables

These detections are rule-based and serve as a proof-of-concept implementation.

---

## Project Structure

```text
Always-On-Security/
│
├── controller/                 # Layer 2: Message Forwarder
├── risk_engine/                # Layer 3/4: Central Processing & Remediation
│   ├── config/                 # YAML configuration (rules, thresholds)
│   └── ...python modules
├── dashboard/
│   ├── app.py
│   ├── Dockerfile
│   ├── requirements.txt
│   └── templates/
│       └── index.html
│
├── security_monitor/
│   ├── Dockerfile
│   ├── start.sh
│   ├── filebeat.yml
│   ├── suricata/
│   └── zeek/
│
├── node_agent/
│   ├── agent.py
│   ├── Dockerfile
│   └── requirements.txt
│
├── scripts/
│   ├── compute_baseline.py
│   ├── beaconing_detector.py
│   └── enforce_segment_iptables.sh
│
├── wazuh/
│   ├── wazuh.py
│   └── Dockerfile
│
├── baselines/
├── data/                       # Shared SQLite Database
│
├── docker-compose.yml
└── .gitignore
```

---

## Prerequisites

Install the following:

### Ubuntu / Linux (Native)

```bash
sudo apt update
sudo apt install git docker.io docker-compose-plugin -y
```

### Windows with WSL (Docker Desktop)

Install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/) and enable WSL integration in:
`Settings → Resources → WSL Integration → Enable your distro`

### Verify Installation

```bash
docker --version
docker compose version
git --version
```

---

## Clone Repository

```bash
git clone <repository-url>
cd Always-On-Security
```

---

## Start the System

Before starting the system for the first time, you must generate the baseline configuration hashes and the `.env` file containing the HMAC secret:

```bash
python3 generate_baseline.py
```

Build and start all services:

```bash
docker compose up --build -d
```

The following containers will start across the segmented Docker networks:

* `controller`
* `risk-engine`
* `dashboard`
* `node1`, `node2`, `node3`, `node4`
* `wazuh`
* `security-monitor`

---

## Access Dashboard

Open your browser and go to:

```text
http://localhost:5000
```

You should see:

* Event statistics
* Node risk scores
* Recent security events
* System activity feed

---

## Generate a Test Alert

**Method 1: Automatic (Built-in Simulator)**
The node agents include a built-in threat simulator that will automatically trigger every few minutes (`node1` has a higher chance). Simply watch the dashboard to see an attack escalate through 4 stages and end in quarantine.

**Method 2: Manual Trigger**
Open a shell inside a node:

```bash
docker exec -it node1 bash
```

Generate high CPU usage:

```bash
yes > /dev/null
```

This should trigger:

* High CPU detection
* Risk score increase
* Event creation
* Dashboard updates
* Node quarantine (when risk ≥ 100)
* Wazuh alert (when node is quarantined)

## Network Threat Tests

The network monitor is designed for the Docker-only HPC simulation, so the easiest tests are container-to-container traffic patterns.

* Port scan: run a simple port sweep from one container against another container's IP on `compute-net` or `storage-net`.
* Unauthorized communication: send traffic from a compute container directly to the management segment.
* Lateral movement: SSH from one node to another, then chain into a third node.
* Beaconing: generate repeated low-byte, fixed-interval connections between the same pair of containers.
* ICMP tunnel / protocol abuse: send large ICMP payloads or mismatched protocol traffic through Suricata-monitored paths.

Expected outputs:

* Suricata EVE JSON notice for port scans and ICMP tunnel patterns
* Zeek notice for unauthorized pairs, fan-out, hop chains, and protocol mismatches
* Python baseline JSON in `baselines/`

Stop the process:

```bash
CTRL + C
```

**Method 3: Advanced Node Attacks**

You can also test the newly added cryptographic and node-level detectors:

**1. Config Tampering (Triggers `CONFIG_TAMPER` alert)**
Modify a monitored configuration file on a running node:
```bash
docker exec node1 sh -c "echo '1.2.3.4 evil.com' >> /etc/hosts"
```

**2. Rogue Node Injection (Triggers `ROGUE_NODE` alert)**
Launch an unauthorized node connecting to the controller. *Note: this requires the `.env` file to be present to grab the HMAC secret.*
```bash
docker run --rm --network always-on-security_security_net \
  -e NODE_NAME=rogue99 \
  -e HMAC_SECRET=$(grep HMAC_SECRET .env | cut -d= -f2) \
  always-on-security-node1
```

**3. Telemetry Tampering / Replay Attacks**
Since all messages are cryptographically signed with HMAC-SHA256, sending raw JSON via `netcat` will be rejected by the Controller. To test `REPLAY_ATTACK` or `TELEMETRY_TAMPER`, you must extract the `HMAC_SECRET` from `.env` and write a custom python script using `pyzmq` to sign and send duplicate `msg_id`s or modify payloads post-signing.

**4. Pre-Flight Config Integrity Block (REC-08)**
The system will now actively refuse to start if its critical configuration files have been maliciously modified or corrupted. To test this:
1. Make a subtle modification to a central config file on the host:
   ```bash
   echo "# Tampered" >> risk_engine/config/rules.yaml
   ```
2. Restart the risk-engine service:
   ```bash
   docker compose restart risk-engine
   ```
3. Watch the startup logs—you will see a large red error, and the container will immediately exit with code 2 rather than starting:
   ```bash
   docker compose logs risk-engine
   ```
4. Revert the file and restart to bring the service back up:
   ```bash
   git checkout risk_engine/config/rules.yaml
   docker compose restart risk-engine
   ```

**5. Pre-Quarantine Forensic Capture (REC-09)**
Trigger a quarantine on any node, then inspect the captured evidence before the container is stopped:
1. Force a node into quarantine by running the built-in threat simulator or manually flooding its risk score.
2. Watch the risk-engine logs for the forensic capture sequence:
   ```bash
   docker compose logs -f risk-engine | grep FORENSICS
   ```
   You will see:
   ```
   [FORENSICS] Starting pre-quarantine capture | node=node1 trigger=QUARANTINE
   [FORENSICS] Artifact saved: /data/forensics/node1_QUARANTINE_20260615T130000Z.json
   [FORENSICS] Capture complete | node=node1
   ```
3. Inspect the JSON artefact on the host:
   ```bash
   docker compose exec risk-engine cat /data/forensics/node1_QUARANTINE_*.json | python3 -m json.tool
   ```
   The file contains the process list, network connections, container state, recent alerts, and recent events — all captured at the exact moment of quarantine.
---

## Useful Commands

```bash
docker compose logs -f              # Stream all logs
docker compose logs -f risk-engine  # Stream risk-engine logs only
docker ps                           # Show status of all containers
docker compose down                 # Stop and clean up the environment
```

---

## Capabilities Demonstrated

* Distributed container monitoring
* Real-time event collection via ZeroMQ
* Risk analysis and scoring
* Automated remediation via Docker API
* Dashboard visualization with Flask + SQLite
* Mock SIEM integration (Wazuh)

### Advanced Security Enhancements (Recent PR/Merge)

The core monitoring architecture has been significantly hardened to simulate an air-gapped, always-on HPC security environment. This update shifts the project from a simple telemetry dashboard to an active threat-defense system. Key additions include:

* **1. Cryptographic Telemetry Protocol (`node_agent/secure_messenger.py`)**
  All inter-node communication over ZeroMQ is now signed with an ephemeral HMAC-SHA256 signature. A shared `.env` secret prevents unauthorized actors from injecting fake telemetry or tampering with resource usage metrics in transit.

* **2. Six-Tier Controller Security Gate (`controller/controller.py`)**
  The central message broker now acts as a hardened security gate. Before forwarding any event to the Risk Engine, it runs 6 distinct checks:
  - **HMAC Verification:** Rejects tampered payloads.
  - **ReplayGuard:** Drops duplicated `msg_id`s within a sliding time window.
  - **FloodGuard:** Enforces rate-limiting to prevent DoS via telemetry flooding.
  - **Rogue Node Detection:** Blocks traffic from unrecognized `machine_id`s.
  - **Impersonation Checks:** Flags nodes trying to spoof trusted identities.

* **3. Node-Level Threat Collection (`node_agent/security_collector.py`)**
  Agents now run a dedicated third thread (`SecurityCollector`) that actively monitors the host for compromise:
  - **Config Tampering:** Hashes critical system files (`/etc/hosts`, `/etc/passwd`) against a generated baseline (`config_hashes.yaml`).
  - **Lateral Movement:** Scans active TCP connections for unexpected outbound SSH activity.
  - **Process Policy Enforcement:** Monitors running processes against an explicit allowlist/denylist.

* **4. Unified Threat Engine (`risk_engine/threat_detector.py` & `alert_manager.py`)**
  The Risk Engine now integrates 10 advanced threat detectors (Rogue Node, Impersonation, Silent Node Timeout, etc.) directly into the cumulative scoring pipeline. Threats are categorized by severity (INFO to CRITICAL) and persisted in a new `security_alerts` SQLite table.

* **5. Dark-Mode Security Dashboard (`dashboard/templates/index.html`)**
  The UI was completely overhauled into a modern, dark-mode security operations center (SOC). It features live-updating SVG threat distribution charts, node trust badges (TRUSTED vs ROGUE), protocol integrity counters, and an XSS-safe dynamic alert feed.

* **6. Pre-flight Config Integrity Check (`scripts/check_config_integrity.py` & `scripts/entrypoint.sh`)**
  Enforces NIST CM-2 / CM-6 / SI-7. A strict startup check added to `risk-engine` and `controller` verifies all service YAML configurations (`rules.yaml`, `allowlist.yaml`, etc.) against a trusted SHA-256 baseline (`config_hashes.yaml`). 
  * If a file has been tampered with, the `entrypoint.sh` wrapper intercepts the startup, prints a detailed error to stdout, and exits with code 2. This prevents the system from ever operating with blinded detection rules or a modified allowlist.
  * Every startup check writes a machine-readable JSON audit record to a persistent `/data/integrity_audits` volume for forensics.

* **7. Pre-Quarantine Forensic Capture (`risk_engine/router.py` & `risk_engine/store.py`)**
  Enforces NIST IR-4 / IR-5. The moment a node is escalated to the `quarantine` bucket, the system freezes evidence *before* the container is stopped:
  * **Process list** — full `ps aux` output from inside the container, capturing every running process at time-of-quarantine.
  * **Network connections** — active TCP connections via `ss -tnp`, revealing any live C2 channels or lateral movement paths.
  * **Container state** — image, PID, network IPs, and mount points from `docker inspect`.
  * **Recent security alerts** — the last 20 security alerts for the node pulled from the DB.
  * **Recent telemetry events** — the last 20 risk-scored events from the `events` table.
  * Evidence is written to **two independent locations**: the `forensic_snapshots` SQLite table (queryable by the dashboard) and a timestamped JSON file under the persistent `/data/forensics` volume (survives container removal and DB resets).

---

## Build-Time Security (CI/CD Pipeline)

Layer 1 of the Always-On Security architecture — shift-left enforcement before any code reaches production.

### What Was Added

| File | Purpose |
|------|---------|
| `.github/workflows/build-time-security.yml` | 10-job security pipeline triggered on every push and PR |
| `.github/workflows/sbom.yml` | SBOM generation on every merge to `main` |
| `.gitleaks.toml` | Secret detection allowlist (HMAC variable refs, FIM integrity hashes) |
| `.yamllint.yml` | YAML linting config for `risk_engine/config/` and `docker-compose.yml` |
| `.checkov.yaml` | IaC skip list for intentional privileged/socket findings |
| `node_agent/requirements.txt` | Pinned dependencies (was inline in Dockerfile) |
| `*/`.dockerignore` (×6)` | Excludes `.env`, `data/`, `__pycache__/` from all build contexts |

### Pipeline Stages

```
Push / PR
    │
    ├── Stage 1 (blocking, serial)
    │   ├── secret-detection   GitLeaks — full git history scan
    │   └── yaml-validation    yamllint + PyYAML safe_load on all configs
    │
    ├── Stage 2 (blocking, parallel)
    │   ├── sast-bandit        Python SAST — blocks on HIGH severity
    │   ├── sast-semgrep       p/python + p/secrets + p/owasp-top-ten
    │   └── shellcheck         Shell script linting (advisory)
    │
    ├── Stage 3 (blocking, parallel)
    │   └── sca-pip-audit      CVE scan on all requirements.txt files
    │
    ├── Stage 4 (advisory, parallel)
    │   ├── hadolint           Dockerfile best-practice linting
    │   ├── checkov            docker-compose.yml IaC scan
    │   └── trivy              Filesystem CVE scan (blocks on CRITICAL)
    │
    └── Security Gate          Final pass/fail verdict for branch protection
```

### Codebase Fixes (Person B track)

- **Dependency pinning** — all `requirements.txt` files pinned to exact versions; `pip-audit` reports zero CVEs
- **`# nosec B108/B103`** — suppressed on intentional `/tmp` fallback path and attack simulator `chmod` with justification comments
- **`# nosemgrep`** — suppressed on Flask `0.0.0.0` binding, mock SIEM `socket.bind`, and attack simulator `chmod`; all with exact rule IDs
- **`.dockerignore`** — added to all 6 service directories; `.env` can no longer be accidentally included in a Docker image layer

### Compliance Mapping

| Check | NIST SP 800-234 | CIS Controls |
|-------|----------------|--------------|
| GitLeaks | SC-12, SC-13 | CIS 3.11, 4.1 |
| YAML validation | CM-2, CM-6 | CIS 4.1 |
| Bandit / Semgrep | SA-11, SI-7 | CIS 16.1, 16.4 |
| pip-audit | SA-12, SI-2 | CIS 2.2, 7.3 |
| Trivy | RA-5, SI-2 | CIS 7.1, 7.3 |
| SBOM (Syft) | SA-12 | CIS 2.1 |

### Known Gaps (Tracked as Issues)

- HMAC\_SECRET passed as plain env var — should migrate to Docker secrets (REC-11)
- Docker base images use floating tags (`python:3.11-slim`) — should pin to digest (DL3007)
- No non-root `USER` instruction in Dockerfiles — containers run as root (DL3002)
- No `HEALTHCHECK` in any Dockerfile (CKV\_DOCKER\_2)
