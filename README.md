# Always-On-Security

A distributed, container-based security monitoring simulation that demonstrates real-time anomaly detection, cumulative risk scoring, automated quarantine, and live dashboard visualization.

---

## Architecture Overview

The system is built as a multi-container Docker application with the following layers:

1. **Layer 1: Node Agents (`node_agent/`)** — Dual-threaded edge agents that collect system telemetry (CPU, memory, process count) while simulating workload states. Includes a built-in threat simulator for testing.
2. **Layer 2: Event Bus & Durability (`controller/`)** — A lightweight message forwarder that receives telemetry via ZeroMQ, stamps events with a sequential offset, and persists state atomically for crash recovery.
3. **Layer 3: Risk Engine (`risk_engine/`)** — A stateless Python microservice that assesses risk. Features context-aware threshold checks, risk decay (self-healing), cross-node correlation, and heartbeat monitoring.
4. **Layer 4: Auto-Remediation (`risk_engine/router.py`)** — Monitors risk levels and routes decisions into buckets (silent, auto, human, quarantine). Initiates container-based node isolation via the Docker API.
5. **Layer 5: Visibility & Alerting (`dashboard/` & `wazuh/`)** — A Flask-based web dashboard showing real-time statistics and node states, plus a simulated Wazuh SIEM manager receiving UDP alerts.

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
* **Telemetry Tampering**: Validates cryptographic HMAC-SHA256 signatures on all messages.

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

Before starting the system for the first time, you must generate the baseline configuration hashes and the `.env` file containing the HMAC secret:

```bash
python3 generate_baseline.py
```

Build and start all 9 services:

```bash
docker compose up --build -d
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
