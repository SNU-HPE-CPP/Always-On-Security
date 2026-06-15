# Always-On Security

A distributed, container-based HPC security monitoring platform that simulates real-time threat detection, cumulative risk scoring, automated enforcement, and live SOC dashboard visualization — architected around the trust-boundary principles of air-gapped, production HPC environments.

---

## Table of Contents

1. [What This Project Does](#1-what-this-project-does)
2. [How It Started — Original Architecture](#2-how-it-started--original-architecture)
3. [The Problem — Why It Was Refactored](#3-the-problem--why-it-was-refactored)
4. [The Refactored Architecture](#4-the-refactored-architecture)
5. [Component Reference](#5-component-reference)
6. [Security Detection Coverage](#6-security-detection-coverage)
7. [File Integrity Monitoring (FIM)](#7-file-integrity-monitoring-fim)
8. [Build-Time Security Pipeline](#8-build-time-security-pipeline)
9. [Getting Started](#9-getting-started)
10. [Testing & Simulation](#10-testing--simulation)
11. [Known Gaps](#11-known-gaps)

---

## 1. What This Project Does

Always-On Security is a multi-container Docker simulation of an HPC cluster security stack. It models the kind of always-on, host-level security instrumentation found in HPE/SGI clusters and Slurm-managed compute environments.

The system continuously monitors a set of tenant workload nodes and enforces security policy without any agent running inside the monitored containers. When a threat is detected — whether a resource anomaly, a tampered config file, a rogue identity, or a network-level attack — the platform scores it, correlates it across nodes, and automatically responds: pausing, stopping, or network-isolating the affected container.

Key capabilities:

- Continuous external telemetry collection from tenant containers via the Docker API
- HMAC-authenticated, replay-protected, flood-guarded message bus (ZeroMQ)
- Cumulative risk scoring with configurable decay (self-healing) and 5-minute hold for high-severity events
- Cross-node attack correlation with risk multipliers
- Automated enforcement: pause, stop, network quarantine, Docker network disconnect
- File Integrity Monitoring (FIM) via Docker's archive API — no exec inside tenant containers
- Passive NIDS via Suricata (signature) and Zeek (behavioural) with a 5-module Python pipeline
- Real-time dark-mode SOC dashboard with live threat charts and node trust badges
- 10-job CI/CD security pipeline with SAST, SCA, secret detection, IaC scanning, and SBOM generation

---

## 2. How It Started — Original Architecture

The original system was built as a functional demo of a security monitoring pipeline. It worked, and demonstrated several realistic ideas, but its trust model was inverted.

### What it had right

- **ZeroMQ message bus** between node agents and a central controller — realistic HPC pattern
- **Cumulative risk scoring with decay** — stateful, context-aware scoring is used in production SIEM platforms
- **Cross-node correlation** — detecting coordinated multi-node attacks is a real detection technique
- **Docker API enforcement** (`container.stop()`, `container.pause()`) — correct placement, infrastructure layer
- **Zeek + Suricata** for network-layer detection — standard HPC NIDS tooling
- **HMAC-SHA256 telemetry signing** — correct cryptographic pattern for authenticating edge telemetry

### What it got wrong

**Security logic ran inside the tenant containers.** Every node agent (`node_agent/agent.py`) contained:

- `psutil` calls scanning the host process table
- `inotify` watches on `/etc/hosts`, `/etc/passwd`, `/etc/ssh/sshd_config`
- Inline golden-copy file restore: `open('/etc/passwd', 'wb').write(golden)`
- Permission restoration: `os.chmod('/etc/passwd', 0o644)`
- Process kill: `psutil.Process(pid).kill()`
- A full attack simulator (Stages 1–5) that modified the very files it was supposed to protect

This means the node containers ran as **root**, held the `HMAC_SECRET` as an environment variable (giving tenant workloads visibility into the security bus), and mounted the security config volume. A compromised tenant workload could read the HMAC secret and forge signed telemetry, suppress its own FIM events, or kill the monitoring thread.

The original architecture looked like this:

```
┌─────────────────────────────────────┐
│  node_agent (RUNS AS ROOT)          │
│  ├─ Telemetry collection (psutil)   │
│  ├─ FIM via inotify                 │
│  ├─ Config tamper detection         │
│  ├─ Process kill enforcement        │
│  ├─ Golden-copy file restore        │
│  ├─ HMAC_SECRET in env              │
│  └─ Built-in attack simulator       │  ← tenant container
└──────────────┬──────────────────────┘
               │ ZMQ :5555
┌──────────────▼──────────────────────┐
│  controller                         │
│  6-gate security validator          │
└──────────────┬──────────────────────┘
               │ ZMQ :5556
┌──────────────▼──────────────────────┐
│  risk-engine                        │
│  Scoring + Correlation + Remediation│
└─────────────────────────────────────┘
```

The six controller security gates (HMAC verify, rogue node, replay guard, flood guard, impersonation, duplicate ID) were correctly placed. The problem was upstream: any tenant with the HMAC secret could craft a valid message that bypassed all of them.

---

## 3. The Problem — Why It Was Refactored

The core issue was a **trust boundary inversion**. In production HPC environments:

- Tenant containers are **untrusted**. They run user workloads. They have no elevated privileges and no visibility into the monitoring infrastructure.
- Security enforcement is performed **externally** by infrastructure-owned services that observe, correlate, and act on the cluster from outside the workload boundary.

Specifically, the pre-refactor design violated the following production principles:

| Violation | Impact |
|---|---|
| Security agents inside tenant containers | Tenant can observe/interfere with monitoring |
| `HMAC_SECRET` passed to node1–node4 | Tenant can forge signed telemetry |
| Containers run as root for FIM/kill | Unnecessary privilege in workload zone |
| Process kill from within monitored container | Enforcer and subject share the same trust domain |
| File restore from within monitored container | Tenant can predict and circumvent restoration logic |
| Built-in attack simulator in production code | Demo artifact with no place in a real deployment |

---

## 4. The Refactored Architecture

The refactor re-draws the trust boundary. The system now has two clearly separated zones:

- **Infrastructure Zone** — services that observe, analyse, and enforce. Trusted. Some run privileged.
- **Workload Zone** — tenant containers. Untrusted. No security agents, no secrets, no root.

### Architecture Diagram

```
  INFRASTRUCTURE ZONE
  ┌────────────────────────────────────────────────────────────────────┐
  │                                                                    │
  │  ┌──────────────────────┐    ┌────────────────────────────────┐   │
  │  │   HOST OBSERVER      │    │      SECURITY MONITOR          │   │
  │  │  (cluster_observer)  │    │                                │   │
  │  │                      │    │  docker_collector  ──┐         │   │
  │  │  Docker stats API    │    │  network_collector ──┤         │   │
  │  │  Docker top API      │    │  threat_correlator   │         │   │
  │  │  Docker archive API  │    │  policy_engine   ────┤         │   │
  │  │  (FIM, no exec)      │    │  event_forwarder ────┘         │   │
  │  │                      │    │                                │   │
  │  │  Process policy check│    │  Suricata (NIDS)               │   │
  │  │  Config tamper check │    │  Zeek (behavioural)            │   │
  │  └──────────┬───────────┘    └──────────────┬─────────────────┘   │
  │             │                               │                     │
  │             │ ZMQ :5555 (HMAC-signed)       │ ZMQ :5555           │
  │             └───────────────┬───────────────┘                     │
  │                             ▼                                     │
  │                  ┌──────────────────────┐                         │
  │                  │      CONTROLLER      │                         │
  │                  │                      │                         │
  │                  │  1. HMAC verify      │                         │
  │                  │  2. Rogue node       │                         │
  │                  │  3. Replay guard     │                         │
  │                  │  4. Flood guard      │                         │
  │                  │  5. Impersonation    │                         │
  │                  │  6. Duplicate ID     │                         │
  │                  └──────────┬───────────┘                         │
  │                             │ ZMQ :5556                           │
  │                             ▼                                     │
  │                  ┌──────────────────────┐                         │
  │                  │     RISK ENGINE      │                         │
  │                  │                      │                         │
  │                  │  Weighted Scoring    │──► SQLite (events.db)   │
  │                  │  Risk Decay          │                         │
  │                  │  Cross-node Corr.    │                         │
  │                  │  Heartbeat Monitor   │                         │
  │                  │  Enforcement Router  │──► Docker API           │
  │                  │  Alert Manager       │──► Wazuh (UDP)          │
  │                  └──────────────────────┘                         │
  │                                                                    │
  │                  ┌──────────────────────┐                         │
  │                  │     DASHBOARD        │                         │
  │                  │  Flask + SQLite      │                         │
  │                  │  localhost:5000      │                         │
  │                  └──────────────────────┘                         │
  └────────────────────────────────────────────────────────────────────┘

  WORKLOAD ZONE  (no HMAC secret, no security agents, no root)
  ┌──────────────────────────────────────────────────────────────────┐
  │  node1    node2    node3    node4                                 │
  │  (customer workload only — no psutil, no inotify, no ZMQ)       │
  └──────────────────────────────────────────────────────────────────┘

  NETWORK SEGMENTS
  compute-net  10.10.1.0/24  (east-west node traffic, internal)
  storage-net  10.10.2.0/24  (shared storage traffic, internal)
  mgmt-net     10.10.3.0/24  (control plane + monitoring, internal)
```

### What Changed in Each Component

#### `node_agent/` — stripped to workload only

Before: root-privileged container running psutil, inotify FIM, process kill, file restore, attack simulator, ZMQ send, HMAC signing.

After: a minimal Python loop that simulates a steady-state workload. No security logic, no elevated privileges, no secrets, no ZMQ socket.

```python
# Everything that's left in node_agent/agent.py after refactoring
while True:
    res = sum(range(100000))   # simulate workload
    time.sleep(5)
```

The Dockerfile drops to a non-root `appuser` (UID 10001). No capabilities are added. No config volumes are mounted. `HMAC_SECRET` is not passed.

#### `host_observer/` — new service

A new privileged infrastructure service (`cluster_observer.py`) takes over everything the node agent used to do from inside the container, but does it externally:

- **Resource telemetry**: Docker stats API → CPU %, memory % (cgroup-accurate, no psutil inside tenant)
- **Process inspection**: Docker `container.top()` → process count and command names checked against `process_policy.yaml`
- **FIM**: Docker `container.get_archive()` → streams the raw file bytes out of the overlay FS, computes SHA-256, compares against baseline — **no exec, no process inside tenant**
- **Signing**: produces HMAC-SHA256-signed telemetry and sends to Controller via ZMQ

#### `security_monitor/` — evolved from passive runner to active pipeline

Before: a bash `start.sh` launcher that started Suricata and Zeek and had no Python logic.

After: a 5-module Python pipeline supervised by `main.py`:

| Module | Role |
|---|---|
| `docker_collector.py` | Subscribes to Docker event stream; emits container lifecycle events |
| `network_collector.py` | Tails Suricata EVE JSON and Zeek notice/conn logs; normalises records |
| `threat_correlator.py` (was `threat_correlator`) | Joins Docker events with network signals; assigns confidence scores |
| `policy_engine.py` | Evaluates fast-path enforcement rules from YAML; acts via Docker API without waiting for score accumulation |
| `event_forwarder.py` | Signs correlated events with HMAC and sends to Controller via ZMQ |

The `policy_engine` can take immediate action (stop, pause, or network-isolate) for critical signals like `ROGUE_NODE`, `NODE_IMPERSONATION`, or `CONFIG_TAMPER` — bypassing the cumulative scoring path entirely.

#### `controller/` — unchanged in logic, now correctly fed

The six-gate security validator is the same. What changed is where its input comes from: previously node agents (tenant-zone); now only infrastructure-zone services (Host Observer and Security Monitor), neither of which holds tenant-accessible secrets.

#### `docker-compose.yml` — trust boundary enforced in configuration

The compose file now documents the two zones explicitly. Node containers receive zero security configuration:

```yaml
# node1 — Workload Zone
node1:
  environment:
    - NODE_NAME=node1   # only this — no HMAC_SECRET, no config paths
  # no volumes, no capabilities added, no docker.sock
```

Versus infrastructure services:

```yaml
# host-observer — Infrastructure Zone
host-observer:
  environment:
    - HMAC_SECRET=${HMAC_SECRET}
    - CONTROLLER_URL=tcp://controller:5555
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock:ro
    - ./risk_engine/config:/opt/security/config:ro
```

---

## 5. Component Reference

### Network Segments

| Network | Subnet | Purpose |
|---|---|---|
| `compute-net` | 10.10.1.0/24 | East-west node traffic; `internal: true` |
| `storage-net` | 10.10.2.0/24 | Shared storage access; `internal: true` |
| `mgmt-net` | 10.10.3.0/24 | Control plane, monitoring, dashboard; `internal: true` |

`security-monitor` is attached to all three segments to enable full traffic inspection. Tenant nodes are attached to one compute or storage segment plus mgmt.

### Service Map

| Container | Zone | IP (mgmt-net) | Key capabilities |
|---|---|---|---|
| `controller` | Infrastructure | 10.10.3.10 | HMAC_SECRET, config:ro |
| `risk-engine` | Infrastructure | 10.10.3.11 | NET_ADMIN, docker.sock:ro |
| `dashboard` | Infrastructure | 10.10.3.20 | shared_data:ro |
| `host-observer` | Infrastructure | 10.10.3.12 | docker.sock:ro, HMAC_SECRET |
| `wazuh` | Infrastructure | 10.10.3.40 | mock SIEM |
| `security-monitor` | Infrastructure | 10.10.3.250 | privileged, NET_ADMIN, NET_RAW, HMAC_SECRET |
| `node1–node4` | Workload | 10.10.3.21–31 | none — unprivileged appuser |

### Risk Engine Config (`risk_engine/config/`)

| File | Purpose |
|---|---|
| `rules.yaml` | Rule definitions with severity and blast-radius weights |
| `thresholds.yaml` | Score thresholds for each enforcement bucket |
| `allowlist.yaml` | Authorised node names and machine IDs |
| `process_policy.yaml` | Denylist / allowlist of process names |
| `node_criticality.yaml` | Per-node criticality multipliers |
| `fast_path_policy.yaml` | Immediate enforcement rules for Policy Engine |
| `config_hashes.yaml` | SHA-256 baselines for monitored config files |

---

## 6. Security Detection Coverage

| Threat | Detection Owner | Enforcement Owner | Mechanism |
|---|---|---|---|
| High CPU/memory/process count | Host Observer | Risk Engine | Docker stats + scoring |
| Suspicious process (denylist) | Host Observer | Risk Engine / Policy Engine | `container.top()` vs `process_policy.yaml` |
| Config file tamper (FIM) | Host Observer | Risk Engine / Policy Engine | `container.get_archive()` SHA-256 vs baseline |
| HMAC failure (telemetry tamper) | Controller | Controller (drop) + Risk Engine (alert) | HMAC-SHA256 verify |
| Rogue node (unknown machine_id) | Controller | Policy Engine (fast-path stop) | Allowlist check |
| Replay attack | Controller | Controller (drop) + Risk Engine (alert) | Sliding window + seq monotonicity |
| Message flooding | Controller | Controller (alert) | Rate window counter |
| Node impersonation | Controller | Policy Engine (fast-path stop) | machine_id change detection |
| Silent node (heartbeat timeout) | Risk Engine | Risk Engine (alert) | 30s telemetry gap |
| Cross-node coordinated attack | Risk Engine | Risk Engine (score multiplier) | 3+ node correlation |
| Port scan / protocol abuse | Security Monitor (Suricata) | Policy Engine | EVE JSON signature match |
| Lateral movement | Security Monitor (Zeek) | Policy Engine | conn.log + notice.log |
| Beaconing | Security Monitor (Zeek / scripts) | Risk Engine | Low-variance interval detection |
| Container lifecycle anomaly | Security Monitor (docker_collector) | Policy Engine | Docker event stream |
| Network fan-out excess | Security Monitor (Zeek) | Policy Engine (network_isolate) | conn.log peer count |

### Enforcement Repertoire

| Action | Trigger | Mechanism |
|---|---|---|
| **Stop container** | Score ≥ quarantine threshold or fast-path CRITICAL | `container.stop()` via Docker API |
| **Pause container** | Lateral movement, moderate-severity fast-path | `container.pause()` via Docker API |
| **Network isolate** | Fan-out excess, high-confidence network threat | Docker `network.disconnect()` from compute-net + storage-net; mgmt-net preserved for forensics |
| **Wazuh alert** | Any quarantine event | UDP syslog to mock SIEM at 10.10.3.40 |

No enforcement action modifies files, kills processes, or alters any state **inside** a tenant container. This is the central invariant of the production enforcement model.

---

## 7. File Integrity Monitoring (FIM)

FIM moved out of the tenant container's inotify thread and into the Host Observer's external inspection loop.

### How it works now

1. `cluster_observer.py` calls `container.get_archive(file_path)` — this is Docker's `cp` API, which streams a tar of the file directly from the container's overlay FS. No process runs inside the tenant.
2. The archive is unpacked in memory, and SHA-256 is computed on the streamed bytes.
3. The hash is compared against the baseline in `config_hashes.yaml` (generated at startup by `generate_baseline.py`). If no pre-defined baseline exists, the first observed hash is recorded and used going forward.
4. On a mismatch, a `FIM_EVENT` payload is constructed and signed with HMAC, then sent to the Controller.
5. The Risk Engine matches the event against FIM rules in `rules.yaml` and places a **5-minute decay hold** on the node — preventing the risk score from self-healing while the tamper remains under investigation.

### FIM Rules

| Rule | Severity | Blast Radius |
|---|---|---|
| `FIM_FILE_CREATED` | 40 | 35 |
| `FIM_FILE_MODIFIED` | 50 | 40 |
| `FIM_PERMISSION_CHANGED` | 60 | 45 |
| `FIM_FILE_DELETED` | 70 | 50 |
| `FIM_BASELINE_TAMPERING` | 90 | 60 |

Files currently monitored: `/etc/hosts`, `/etc/passwd`, `/etc/ssh/sshd_config`.

---

## 8. Build-Time Security Pipeline

Two GitHub Actions workflows enforce shift-left security on every push and pull request.

### Pipeline Stages

```
Push / PR
    │
    ├── Stage 1 — Blocking, serial
    │   ├── secret-detection    GitLeaks full history scan
    │   └── yaml-validation     yamllint + PyYAML safe_load on all configs
    │
    ├── Stage 2 — Blocking, parallel
    │   ├── sast-bandit         Python SAST; blocks on HIGH severity
    │   ├── sast-semgrep        p/python + p/secrets + p/owasp-top-ten
    │   └── shellcheck          Shell script linting (advisory)
    │
    ├── Stage 3 — Blocking, parallel
    │   └── sca-pip-audit       CVE scan across all requirements.txt files
    │
    ├── Stage 4 — Advisory, parallel
    │   ├── hadolint            Dockerfile best-practice lint
    │   ├── checkov             docker-compose.yml IaC scan
    │   └── trivy               Filesystem CVE scan (blocks on CRITICAL)
    │
    └── Security Gate           Final pass/fail for branch protection
```

On every merge to `main`, a second workflow (`sbom.yml`) generates a software bill of materials using Syft.

### Compliance Mapping

| Check | NIST SP 800-234 | CIS Controls |
|---|---|---|
| GitLeaks | SC-12, SC-13 | CIS 3.11, 4.1 |
| YAML validation | CM-2, CM-6 | CIS 4.1 |
| Bandit / Semgrep | SA-11, SI-7 | CIS 16.1, 16.4 |
| pip-audit | SA-12, SI-2 | CIS 2.2, 7.3 |
| Trivy | RA-5, SI-2 | CIS 7.1, 7.3 |
| SBOM (Syft) | SA-12 | CIS 2.1 |

---

## 9. Getting Started

### Prerequisites

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install git docker.io docker-compose-plugin -y

# Verify
docker --version
docker compose version
```

For Windows, install [Docker Desktop](https://www.docker.com/products/docker-desktop/) and enable WSL integration.

### Setup

Clone the repo and generate the HMAC secret and config baselines:

```bash
git clone <repository-url>
cd Always-On-Security
python3 generate_baseline.py
```

This creates a `.env` file containing `HMAC_SECRET` and populates `risk_engine/config/config_hashes.yaml` with baseline SHA-256 hashes of the monitored config files.

### Start

```bash
docker compose up --build -d
```

Containers started:

| Container | Role |
|---|---|
| `controller` | Message security gate |
| `risk-engine` | Scoring, correlation, enforcement |
| `dashboard` | Web UI at localhost:5000 |
| `host-observer` | External telemetry and FIM collection |
| `node1`, `node2`, `node3`, `node4` | Tenant workloads |
| `wazuh` | Mock SIEM |
| `security-monitor` | Suricata + Zeek + Python pipeline |

### Access Dashboard

```
http://localhost:5000
```

The dashboard shows:
- Per-node risk scores and trust status (TRUSTED / ROGUE)
- Live threat distribution chart (SVG, auto-refreshing)
- Recent security events feed with FIM details
- Protocol integrity counters (HMAC failures, replay attempts)

### Useful Commands

```bash
docker compose logs -f                 # Stream all logs
docker compose logs -f risk-engine     # Risk engine only
docker compose logs -f host-observer   # External telemetry collector
docker compose logs -f security-monitor # Network pipeline
docker ps                              # Container status
docker compose down                    # Stop and clean up
```

---

## 10. Testing & Simulation

The built-in attack simulator has been removed from the tenant containers. Threats are now injected externally, which is both more realistic and safer.

### Resource Anomaly

Trigger high CPU from outside the container:

```bash
# Run a stress process inside a node — this is now the *only* thing
# an attacker can do from the workload zone (they have no security visibility)
docker exec -it node1 bash -c "yes > /dev/null &"
```

The Host Observer will detect the CPU spike via Docker stats and send a scored event to the Risk Engine.

### Config Tamper (FIM)

```bash
# Modify a monitored file from outside the container
docker exec node1 sh -c "echo '1.2.3.4 evil.com' >> /etc/hosts"
```

The Host Observer will detect the SHA-256 mismatch on the next poll cycle and generate a `FIM_FILE_MODIFIED` event.

### Rogue Node Injection

```bash
docker run --rm --network always-on-security_mgmt-net \
  -e NODE_NAME=rogue99 \
  always-on-security-node1
```

The Controller rejects the message (node not in allowlist) and forwards a `ROGUE_NODE` alert to the Risk Engine. The Policy Engine triggers a fast-path stop.

### Network Threat Tests

The Security Monitor inspects all three network segments. Effective test patterns:

```bash
# Port scan — triggers Suricata EVE JSON alert
docker exec node2 nmap -sS 10.10.1.0/24

# Lateral movement — SSH hop between compute nodes
docker exec node1 ssh 10.10.1.22

# Beaconing — fixed-interval, low-byte connections
# (use scripts/beaconing_detector.py to analyse conn logs)

# Unauthorized segment crossing — compute node to mgmt-net target
docker exec node1 curl http://10.10.3.10
```

Expected outputs: Suricata EVE JSON notice, Zeek notice.log entry, Risk Engine alert, Policy Engine enforcement action.

### Replay Attack

Send a previously seen message with a duplicate `msg_id`. The Controller's `ReplayGuard` will reject it within the sliding window and forward a `REPLAY_ATTACK` alert downstream.

---

## 11. Known Gaps

These are tracked issues for future hardening:

| Issue | Category | Notes |
|---|---|---|
| `HMAC_SECRET` passed as plain env var | Secret management | Should migrate to Docker secrets or a secrets manager |
| Base images use floating tags (`python:3.11-slim`) | Supply chain | Should pin to image digest to prevent tag mutation |
| No `USER` instruction in some Dockerfiles | Privilege | Some containers still run as root; tracked under REC-01 / REC-02 |
| No `HEALTHCHECK` in Dockerfiles | Availability | Docker cannot auto-restart unhealthy containers |
| `security-monitor` requires `privileged: true` | Attack surface | Acceptable for Infrastructure Zone (Suricata/Zeek need raw packet capture); not present in Workload Zone |
| Host Observer polls every 5 seconds | Detection latency | Near-real-time; not kernel-event-driven |
| Docker socket mounted read-only, not proxied | API surface | A Docker socket proxy (`docker-socket-proxy`) would further restrict the API surface exposed to each container |
