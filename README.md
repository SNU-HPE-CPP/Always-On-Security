# Always-On-Security

A distributed, container-based security monitoring simulation that demonstrates real-time anomaly detection, cumulative risk scoring, automated quarantine, and live dashboard visualization.

---

## Architecture Overview

The system is built as a multi-container Docker application with the following layers:

1. **Layer 1: Node Agents (`node_agent/`)** — Dual-threaded edge agents that collect system telemetry (CPU, memory, process count) while simulating workload states. Includes a built-in threat simulator for testing.
2. **Layer 2: Event Bus & Durability (`controller/`)** — A lightweight message forwarder that receives telemetry via ZeroMQ, stamps events with a sequential offset, and persists state atomically for crash recovery.
3. **Layer 3: Risk Engine (`risk_engine/`)** — A stateless Python microservice that assesses risk. Features context-aware threshold checks, risk decay (self-healing), cross-node correlation, and heartbeat monitoring.
4. **Layer 4: Auto-Remediation & Human Review (`risk_engine/router.py`)** — Monitors risk levels and routes decisions into buckets (silent, auto, human, quarantine). Pauses nodes awaiting manual approval and stops quarantined nodes.
5. **Layer 5: Visibility & Alerting (`dashboard/` & `wazuh/`)** — A Flask-based web dashboard showing real-time statistics and node states, plus a simulated Wazuh SIEM manager receiving UDP alerts.

```
                ┌──────────────────────────────────┐
                │          RISK ENGINE             │
                │  YAML Rules & Scoring Pipeline   │
                │  Heartbeat & Correlation         │
                │  Remediation Router              │──► Docker API (Quarantine & Pause)
                │  DB Writer                       │──► SQLite
                └───────────────▲──────────────────┘
                                │ ZMQ :5556
                ┌───────────────┴──────────────────┐
                │          CONTROLLER              │
                │  Message Forwarder & Offsets     │
                └───────────────▲──────────────────┘
                                │ ZMQ :5555
                ┌───────────────┴──────────────────┐
                │          NODE AGENTS             │  ×4 (node1 to node4)
                │  Telemetry & Threat Simulator    │
                └──────────────────────────────────┘

                ┌───────────────┐  ┌───────────────┐
                │   DASHBOARD   │  │     WAZUH     │
                │ localhost:5000│  │ Mock SIEM :514│
                └───────────────┘  └───────────────┘
```

---

## Key Features

* **Cumulative Risk Scoring & Self-Healing:** The risk engine maintains a cumulative risk score for each node using severity, blast radius, and asset criticality. If anomalies cease, the risk score decays slowly back to 0.
* **Heartbeat Monitor:** Detects silent node failures. If a node fails to send telemetry for 30 seconds, it is marked as unresponsive (paused, quarantined, or awaiting approval nodes are bypassed to avoid false positives).
* **Cross-Node Correlation:** Detects coordinated attacks hitting 3+ nodes simultaneously within a 10-minute window and applies a `1.5x` risk multiplier.
* **Human-in-the-Loop Review Track:** If a node's cumulative risk score rises into the `71-100` range, the risk engine issues a `docker pause` via the Docker API to freeze the container. The operator must review contributing threat events in the live dashboard, and click "Execute Remediation Playbook" to run a simulated remediation pipeline (sequentially executing `mock_slurm`, `mock_ansible`, and `mock_openscap`), which unpauses the container and resets its risk score.
* **Automated Quarantine:** Once a node's cumulative risk score exceeds `100`, the system automatically quarantines the node by stopping its container (`docker stop`) via the Docker API.
* **Mock Wazuh Integration:** A simulated Wazuh SIEM manager receives and displays security alerts via UDP when events escalate to Warning, High, or Critical thresholds.

---

## Risk Scoring & Decision Pipeline

The risk engine dynamically calculates risk increments for each incoming telemetry event using the following formula:

$$\text{Event Score} = \max_{\text{matched rules}} \left( \frac{\text{Severity} \times \text{Blast Radius} \times \text{Asset Criticality}}{1000} \right) \times \text{Correlation Multiplier}$$

* **Asset Criticality**: Configured in `node_criticality.yaml` (`node1`: 3, `node2`: 3, `node3`: 5, `node4`: 20, `default`: 4).
* **Correlation Multiplier**: `1.5` if a coordinated attack is detected on 3 or more nodes within a 10-minute window.
* **Self-Healing (Risk Decay)**: When a node's metrics return to normal, its cumulative risk score automatically decays by `5.0` points per normal event cycle down to `0.0`.

### Security Detection Rules (Configured in rules.yaml & agent.py)

| Rule ID | Metric / Trigger Condition | Severity | Blast Radius |
| :--- | :--- | :---: | :---: |
| **HIGH_CPU** | CPU Usage > 80% | 20 | 25 |
| **HIGH_MEMORY** | Memory Usage > 85% | 20 | 25 |
| **PROCESS_EXPLOSION** | Total Process Count > 300 | 30 | 30 |
| **SUSPICIOUS_PROCESS** | Execution of hacking tools (e.g. `nmap`, `hydra`, `nc`, `stress`) | 40 | 40 |
| **FAILED_LOGIN_BURST** | Failed login attempts > 5 within a cycle | 55 | 60 |
| **PRIVILEGE_ESCALATION** | Privilege escalation attempts > 0 within a cycle | 80 | 85 |

### Mitigation & Routing Action Buckets

Based on the cumulative risk score, the nodes are routed into four distinct buckets (defined in `thresholds.yaml`):

| Cumulative Score | Bucket | Action Taken |
| :--- | :--- | :--- |
| **0 – 30** | `silent` | No action taken. |
| **31 – 70** | `auto` | Auto-remediation warning logged and sent to Wazuh SIEM. |
| **71 – 100** | `human` | **Human-in-the-Loop:** Container is frozen via `docker pause`. Operator must review incidents on the dashboard and manually approve remediation to unpause. |
| **> 100** | `quarantine` | **Quarantine:** Container is stopped via `docker stop` and a critical SIEM alert is dispatched. |

---

## Suspicious Activity Detection

Currently, a node is marked as suspicious if it exhibits one or more of the following:

* High CPU usage (> 80%)
* High memory usage (> 85%)
* Excessive number of running processes (> 300)
* Running suspicious process names (e.g., `stress`, `nmap`, `hydra`, `netcat`, `metasploit`, etc.)
* Burst of failed login attempts (> 5)
* Privilege escalation attempts (> 0)

These detections are monitored by the edge node agent and forwarded via the ZeroMQ event bus.

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
├── node_agent/
│   ├── agent.py
│   ├── Dockerfile
│   └── requirements.txt
│
├── wazuh/
│   ├── wazuh.py
│   └── Dockerfile
│
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

Build and start all 9 services:

```bash
docker compose up --build
```

The following containers will start inside the `security_net` bridge network:

* `controller`
* `risk-engine`
* `dashboard`
* `node1`, `node2`, `node3`, `node4`
* `wazuh`

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
The node agents include a built-in threat simulator that will automatically trigger randomly (`node1` has a higher trigger chance). Once triggered, the simulator escalates through 5 stages:
1. **Stage 1 (CPU Anomaly)**: Sets CPU to 92.5%, triggering a `HIGH_CPU` event.
2. **Stage 2 (Memory Anomaly)**: Sets memory to 88.0%, triggering a `HIGH_MEMORY` event.
3. **Stage 3 (Process Explosion & logins)**: Sets process count to 310 and simulates 8-20 failed logins, triggering `PROCESS_EXPLOSION` and `FAILED_LOGIN_BURST` events.
4. **Stage 4 (Suspicious Binary)**: Spawns simulated `hydra` execution, triggering `SUSPICIOUS_PROCESS`.
5. **Stage 5 (Privilege Escalation)**: Simulates 1-5 privilege escalation attempts, triggering `PRIVILEGE_ESCALATION`.

Watch the live dashboard to see these threats escalate the node's cumulative risk score. Since the score will land in the `71-100` range, the container will automatically pause (status: `awaiting_approval`). Clicking **Review & Approve** in the dashboard lets you inspect the incident timeline and trigger the simulated remediation playbook to unpause the node.

**Method 2: Manual Trigger**
Open a shell inside one of the node containers:

```bash
docker exec -it node1 bash
```

To trigger high CPU usage manually, run:

```bash
yes > /dev/null
```

This will trigger a `HIGH_CPU` alert, initiating risk accumulation and real-time visualization on the dashboard. Stop the process by pressing `CTRL + C`.

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
