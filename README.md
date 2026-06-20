# Always-On Security

A distributed, container-based HPC security monitoring platform that simulates real-time threat detection, cumulative risk scoring, automated enforcement, and live SOC dashboard visualization — architected around the trust-boundary principles of air-gapped, production HPC environments.

---

## Table of Contents

1. [What This Project Does](#1-what-this-project-does)
2. [Architecture](#2-architecture)
3. [Component Reference](#3-component-reference)
4. [Detection Coverage](#4-detection-coverage)
5. [Build-Time Security Pipeline](#5-build-time-security-pipeline)
6. [Getting Started](#6-getting-started)
7. [Testing & Simulation](#7-testing--simulation)
8. [Removed Components](#8-removed-components)
9. [Known Gaps](#9-known-gaps)

---

## 1. What This Project Does

Always-On Security is a multi-container Docker simulation of an HPC cluster security stack. It models the kind of always-on, host-level security instrumentation found in HPE/SGI clusters and Slurm-managed compute environments.

The system continuously monitors tenant workload nodes and enforces security policy without any agent running inside the monitored containers. When a threat is detected — a runtime configuration change, a mismatched image digest, a Falco-observed privilege escalation, a Suricata network alert, or a protocol attack — the platform scores it, correlates it across signals and nodes, and automatically responds: pausing, stopping, or network-isolating the affected container.

**Core design invariants (non-negotiable):**

- Tenant workload containers are untrusted
- No security agents run inside workload containers
- No secrets are exposed to workload containers
- All detection, correlation, and enforcement occurs from the Infrastructure Zone
- No enforcement action modifies files or kills processes inside a tenant container

---

## 2. Architecture

### Trust Zone Diagram

```
  INFRASTRUCTURE ZONE
  ┌──────────────────────────────────────────────────────────────────────────┐
  │                                                                          │
  │  ┌─────────────────────────┐         ┌────────────────────────────────┐ │
  │  │     HOST OBSERVER       │         │       SECURITY MONITOR         │ │
  │  │  (cluster_observer.py)  │         │                                │ │
  │  │                         │         │  docker_collector  ──┐         │ │
  │  │  Docker stats API       │         │  falco_collector   ──┤         │ │
  │  │  Image attestation      │         │  network_collector ──┤         │ │
  │  │  Runtime drift detect.  │         │  threat_correlator   │         │ │
  │  │  Infra config integrity │         │  policy_engine   ────┤         │ │
  │  │                         │         │  event_forwarder ────┘         │ │
  │  │  Via docker-socket-proxy│         │                                │ │
  │  └──────────┬──────────────┘         │  Suricata (NIDS, signatures)   │ │
  │             │                        │  Zeek (behavioural network)    │ │
  │             │                        └──────────────┬─────────────────┘ │
  │             │                                       │                   │
  │  ┌──────────┴──────────────┐         ┌─────────────┴──────────────────┐ │
  │  │        FALCO            │         │   DOCKER SOCKET PROXY          │ │
  │  │  Host-level runtime     │         │   (tecnativa/docker-socket-    │ │
  │  │  security sensor        │         │    proxy)                      │ │
  │  │  pid: host, privileged  │         │   10.10.3.5:2375               │ │
  │  │  Writes → falco_logs/   │         │   Allowlists API endpoints     │ │
  │  └─────────────────────────┘         └────────────────────────────────┘ │
  │             │                                                            │
  │             │ ZMQ :5555 (HMAC-signed)                                    │
  │             ▼                                                            │
  │  ┌──────────────────────────┐                                           │
  │  │        CONTROLLER        │                                           │
  │  │                          │                                           │
  │  │  1. HMAC verify          │                                           │
  │  │  2. Rogue node           │                                           │
  │  │  3. Replay guard         │                                           │
  │  │  4. Flood guard          │                                           │
  │  │  5. Impersonation detect │                                           │
  │  │  6. Duplicate ID         │                                           │
  │  └──────────┬───────────────┘                                           │
  │             │ ZMQ :5556                                                 │
  │             ▼                                                            │
  │  ┌──────────────────────────┐                                           │
  │  │       RISK ENGINE        │                                           │
  │  │                          │                                           │
  │  │  Weighted scoring        │──► SQLite (events.db)                    │
  │  │  Risk decay              │                                           │
  │  │  Cross-node correlation  │                                           │
  │  │  Multi-signal correlation│                                           │
  │  │  Heartbeat monitor       │                                           │
  │  │  Enforcement router      │──► Docker Socket Proxy                   │
  │  │  Alert manager           │──► Wazuh (UDP syslog)                    │
  │  └──────────────────────────┘                                           │
  │                                                                          │
  │  ┌──────────────────────────┐                                           │
  │  │       DASHBOARD          │                                           │
  │  │  Flask + SQLite          │                                           │
  │  │  localhost:5000          │                                           │
  │  └──────────────────────────┘                                           │
  └──────────────────────────────────────────────────────────────────────────┘

  WORKLOAD ZONE  (no secrets · no agents · no root · no docker.sock)
  ┌──────────────────────────────────────────────────────────────────────────┐
  │  node1       node2       node3       node4                               │
  │  UID 10001   UID 10001   UID 10001   UID 10001                           │
  │  (customer workload only — no psutil, no inotify, no ZMQ, no HMAC)      │
  └──────────────────────────────────────────────────────────────────────────┘

  NETWORK SEGMENTS
  compute-net   10.10.1.0/24   east-west node traffic  (internal: true)
  storage-net   10.10.2.0/24   shared storage traffic  (internal: true)
  mgmt-net      10.10.3.0/24   control plane           (internal: true)
  host-access   bridge         dashboard port only     (non-internal)
```

### Data Flow

```
  Docker Daemon
       │
       ├──► docker-socket-proxy :2375
       │         │
       │         ├── host-observer   (stats, inspect, image digest)
       │         ├── security-monitor (event stream)
       │         └── risk-engine     (pause, stop, network disconnect)
       │
       └──► falco (privileged, pid:host)
                 │
                 └── falco_logs volume ──► security-monitor/falco_collector
```

---

## 3. Component Reference

### Service Map

| Container | Zone | IP (mgmt-net) | Key Capabilities |
|---|---|---|---|
| `docker-socket-proxy` | Infrastructure | 10.10.3.5 | Proxies docker.sock; allowlists endpoints |
| `controller` | Infrastructure | 10.10.3.10 | HMAC_SECRET, config:ro |
| `risk-engine` | Infrastructure | 10.10.3.11 | NET_ADMIN, via socket proxy |
| `dashboard` | Infrastructure | 10.10.3.20 | shared_data:ro, port 5000 |
| `host-observer` | Infrastructure | 10.10.3.12 | HMAC_SECRET, via socket proxy |
| `wazuh` | Infrastructure | 10.10.3.40 | mock SIEM (UDP 5514) |
| `falco` | Infrastructure | 10.10.3.45 | privileged, pid:host |
| `security-monitor` | Infrastructure | 10.10.3.250 | privileged, NET_ADMIN, NET_RAW |
| `node1–node4` | Workload | 10.10.3.21–31 | None — unprivileged appuser (UID 10001) |

### Network Segments

| Network | Subnet | Notes |
|---|---|---|
| `compute-net` | 10.10.1.0/24 | East-west node traffic; `internal: true` |
| `storage-net` | 10.10.2.0/24 | Shared storage; `internal: true` |
| `mgmt-net` | 10.10.3.0/24 | Control plane + monitoring; `internal: true` |
| `host-access` | bridge | Dashboard port publication only |

`security-monitor` is attached to all three segments for full-spectrum traffic inspection.

### Risk Engine Config (`risk_engine/config/`)

| File | Purpose |
|---|---|
| `rules.yaml` | Rule definitions with severity and blast-radius weights |
| `thresholds.yaml` | Score thresholds for enforcement buckets |
| `allowlist.yaml` | Authorised node names and security parameters |
| `node_criticality.yaml` | Per-node criticality multipliers |
| `fast_path_policy.yaml` | Immediate pre-score enforcement rules |
| `approved_images.yaml` | Expected image digests per workload node |
| `runtime_baseline.yaml` | Expected runtime config (user, caps, networks, mounts) |

### Host Observer — Detection Subsystems

#### 1. Image Attestation
Reads the running container's image ID and repo digests via Docker inspect. Compares against `approved_images.yaml`. Generates `IMAGE_MISMATCH` or `UNAPPROVED_IMAGE` events with full evidence. No container access required.

#### 2. Runtime Drift Detection
Extracts live container config from Docker inspect: user, capabilities, bind mounts, network attachments, restart policy, security options. Compares against `runtime_baseline.yaml`. Generates `RUNTIME_DRIFT` events with a per-field diff. Catches: container suddenly running as root, unexpected capability added, unexpected volume mount or network connection.

#### 3. Infrastructure Config Integrity
Computes SHA-256 of infrastructure-owned YAML files at startup. Rechecks every 30 seconds. Generates `CONFIG_DRIFT`, `POLICY_TAMPER`, or `ALLOWLIST_TAMPER` events. Only monitors security infrastructure files — never customer files.

### Security Monitor — Pipeline Modules

| Module | Input | Output |
|---|---|---|
| `docker_collector.py` | Docker event stream | exec, restart loop, rename, network events |
| `falco_collector.py` | `/var/log/falco/events.json` | FALCO_ALERT, REVERSE_SHELL, PRIV_ESC_ATTEMPT, CONTAINER_ESCAPE_ATTEMPT |
| `network_collector.py` | Suricata EVE JSON, Zeek notice/conn logs | NETWORK_THREAT, behavioural notices |
| `threat_correlator.py` | All sources above | Joins events; escalates correlated threats |
| `policy_engine.py` | Correlated events | Fast-path enforcement before scoring |
| `event_forwarder.py` | Policy-passed events | HMAC-signed ZMQ send to controller |

### Risk Engine — Correlation

Two correlation modes run in parallel:

**Cross-node correlation** (original): same rule fires on ≥3 distinct nodes within 600s → 1.5× score multiplier.

**Multi-signal correlation** (new): specific combinations of threat types on the same node within a configurable window trigger higher-confidence findings:

| Combination | Window | Multiplier | Label |
|---|---|---|---|
| REVERSE_SHELL + NETWORK_THREAT | 120s | 2.5× | High Confidence Compromise |
| FALCO_ALERT + RUNTIME_DRIFT + NETWORK_THREAT | 300s | 3.0× | Critical Multi-Signal Risk |
| CONTAINER_EXEC + PRIV_ESC_ATTEMPT | 180s | 2.5× | Active Attack Chain |
| IMAGE_MISMATCH + RUNTIME_DRIFT | 600s | 2.0× | Deployment Tamper |
| ALLOWLIST_TAMPER + ROGUE_NODE | 600s | 3.0× | Coordinated Intrusion |
| CONTAINER_ESCAPE_ATTEMPT + PRIV_ESC_ATTEMPT | 120s | 3.0× | Container Escape |

### Docker Socket Proxy

All infrastructure services that previously mounted `/var/run/docker.sock` directly now talk to `docker-socket-proxy:2375` via `DOCKER_HOST=tcp://docker-socket-proxy:2375`. The proxy allowlists only the API endpoints each service actually needs:

| API | Enabled | Consumers |
|---|---|---|
| `GET /containers/*` | ✅ | host-observer, security-monitor, risk-engine |
| `GET /events` | ✅ | security-monitor |
| `GET /images/*` | ✅ | host-observer |
| `GET /networks/*` | ✅ | risk-engine |
| `POST /containers/*/pause` | ✅ | risk-engine |
| `POST /containers/*/stop` | ✅ | risk-engine |
| `POST /networks/*/disconnect` | ✅ | risk-engine |
| All other endpoints | ❌ | — |

---

## 4. Detection Coverage

### Event Types and Scoring

| Event Type | Source | Severity | Blast Radius | Notes |
|---|---|---|---|---|
| `ROGUE_NODE` | Controller | 50 | 30 | Node not in allowlist |
| `NODE_IMPERSONATION` | Controller | 60 | 40 | machine_id changed |
| `REPLAY_ATTACK` | Controller | 45 | 25 | Stale/duplicate message |
| `FLOOD_ATTACK` | Controller | 30 | 15 | Rate limit exceeded |
| `TELEMETRY_TAMPER` | Controller | 50 | 30 | HMAC failure |
| `SILENT_NODE` | Risk Engine | 40 | 20 | Heartbeat timeout |
| `LATERAL_MOVEMENT` | Security Monitor | 55 | 35 | SSH anomaly |
| `NETWORK_THREAT` | Security Monitor | 55 | 35 | Suricata/Zeek alert |
| `IMAGE_MISMATCH` | Host Observer | 65 | 40 | Digest mismatch vs approved_images.yaml |
| `UNAPPROVED_IMAGE` | Host Observer | 55 | 35 | No approved digest on record |
| `RUNTIME_DRIFT` | Host Observer | 60 | 40 | Cap/volume/network/user drift |
| `CONFIG_DRIFT` | Host Observer | 55 | 35 | Infra config file modified |
| `POLICY_TAMPER` | Host Observer | 65 | 45 | Security policy file modified |
| `ALLOWLIST_TAMPER` | Host Observer | 70 | 50 | Allowlist file modified |
| `CONTAINER_EXEC` | Security Monitor | 45 | 25 | exec_create on workload container |
| `UNEXPECTED_EXEC` | Security Monitor | 55 | 35 | exec_start on workload container |
| `SUSPICIOUS_RESTART_PATTERN` | Security Monitor | 40 | 20 | ≥5 restarts in 120s |
| `UNEXPECTED_NETWORK_ATTACH` | Security Monitor | 50 | 30 | Network connect/disconnect |
| `FALCO_ALERT` | Security Monitor | 50 | 30 | Generic Falco rule match |
| `REVERSE_SHELL` | Security Monitor | 80 | 60 | Falco reverse shell rule |
| `PRIV_ESC_ATTEMPT` | Security Monitor | 70 | 50 | Falco privilege escalation rule |
| `CONTAINER_ESCAPE_ATTEMPT` | Security Monitor | 90 | 70 | Falco container escape rule |

### Enforcement Actions

| Action | Trigger | Mechanism |
|---|---|---|
| **Stop container** | Score ≥ quarantine, IMAGE_MISMATCH, UNAPPROVED_IMAGE, REVERSE_SHELL, CONTAINER_ESCAPE_ATTEMPT | `container.stop()` via Docker API |
| **Pause container** | Lateral movement, RUNTIME_DRIFT, PRIV_ESC_ATTEMPT | `container.pause()` via Docker API |
| **Network isolate** | Fan-out, UNEXPECTED_NETWORK_ATTACH, POLICY_TAMPER | `network.disconnect()` compute-net + storage-net |
| **Wazuh alert** | Any auto/human/quarantine bucket event | UDP syslog to 10.10.3.40:5514 |

No enforcement action executes code, modifies files, or kills processes inside a tenant container.

### Risk Scoring Buckets

| Bucket | Score Range | Action |
|---|---|---|
| `silent` | 0–30 | Monitor only |
| `auto` | 31–70 | Wazuh alert + auto-remediation |
| `human` | 71–100 | Pause + human review |
| `quarantine` | > 100 | Stop + network isolate |

Scores decay at 5.0 per cycle when no rules match (self-healing after threat activity subsides).

---

## 5. Build-Time Security Pipeline

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

---

## 6. Getting Started

### Prerequisites

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install git docker.io docker-compose-plugin -y

# Arch
sudo pacman -S docker docker-compose

# Verify
docker --version
docker compose version
```

### Setup

```bash
git clone <repository-url>
cd Always-On-Security
cp .env.example .env          # edit HMAC_SECRET if desired
```

After first `docker compose up`, capture the runtime and image baselines from a known-good state:

```bash
# Capture image digests
python3 scripts/capture_approved_images.py

# Capture runtime config baseline
python3 scripts/capture_runtime_baseline.py
```

Commit the updated `risk_engine/config/approved_images.yaml` and `runtime_baseline.yaml`. Regenerate these after every intentional image rebuild or compose change.

### Start

```bash
docker compose up --build
```

Services started:

| Container | Role |
|---|---|
| `docker-socket-proxy` | Docker API gateway |
| `controller` | Message security gate (6 checks) |
| `risk-engine` | Scoring, correlation, enforcement |
| `dashboard` | Web UI at http://localhost:5000 |
| `host-observer` | Image attestation, runtime drift, infra config integrity |
| `node1–node4` | Tenant workloads |
| `wazuh` | Mock SIEM |
| `security-monitor` | Suricata + Zeek + Falco pipeline |
| `falco` | Host-level runtime security sensor |

### Access Dashboard

```
http://localhost:5000
```

The dashboard shows:
- Per-node risk scores, trust status, and enforcement state
- Live threat distribution chart (auto-refresh 5s)
- Security alert feed with severity filter
- Protocol integrity counters (HMAC failures, replay attempts, image mismatches, Falco alerts)
- Node identity registry

### Useful Commands

```bash
docker compose logs -f                   # Stream all logs
docker compose logs -f risk-engine       # Risk engine only
docker compose logs -f host-observer     # Image/drift/config checks
docker compose logs -f security-monitor  # Suricata/Zeek/Falco pipeline
docker compose logs -f falco             # Falco raw events
docker ps                                # Container status
docker compose down                      # Stop and clean up
```

---

## 7. Testing & Simulation

Threats are injected externally. Workload containers have no visibility into the security infrastructure.

### Image Attestation Test

Update `approved_images.yaml` with a wrong digest, then restart host-observer:

```bash
# Edit risk_engine/config/approved_images.yaml
# Set node1 to a fake digest: sha256:deadbeef...

docker compose restart host-observer
# → IMAGE_MISMATCH event appears in dashboard within 5 seconds
```

Or pull a different image tag and repoint node1:

```bash
docker tag always-on-security-node1 tampered-node1
# → UNAPPROVED_IMAGE if digest doesn't match
```

### Runtime Drift Test

Attach an unexpected network to a running workload container:

```bash
docker network connect always-on-security_storage-net node1
# → RUNTIME_DRIFT event: field=networks, unexpected attachment detected
```

Or add a capability:

```bash
docker update --cap-add SYS_PTRACE node2
# → RUNTIME_DRIFT event: field=cap_add
```

### Infrastructure Config Tamper Test

Edit a policy file while the system is running:

```bash
echo "# tamper" >> risk_engine/config/rules.yaml
# → POLICY_TAMPER event within 30 seconds
```

### Falco Test

Spawn a shell inside a workload container (this triggers Falco's "Terminal shell in container" rule):

```bash
docker exec -it node1 bash
# → FALCO_ALERT or REVERSE_SHELL event in security-monitor pipeline
```

### Docker Exec Detection

```bash
docker exec node2 id
# → CONTAINER_EXEC + UNEXPECTED_EXEC events from docker_collector
```

### Suspicious Restart Pattern

```bash
for i in $(seq 1 6); do docker restart node3; done
# → SUSPICIOUS_RESTART_PATTERN event after 5th restart within 120s
```

### Rogue Node Injection

```bash
docker run --rm --network always-on-security_mgmt-net \
  -e NODE_NAME=rogue99 \
  always-on-security-node1
# → ROGUE_NODE alert, node blacklisted, fast-path stop
```

The Controller rejects the message (node not in allowlist), dynamically appends the node name to `/data/rogue_blacklist.yaml`, and forwards a single `ROGUE_NODE` alert to the Risk Engine (where the Policy Engine triggers a fast-path stop). Any subsequent messages from this rogue node are silently dropped by the Controller to prevent alert flooding.
### Replay Attack

Send a previously seen message with a duplicate `msg_id`. The Controller's `ReplayGuard` rejects it and forwards a `REPLAY_ATTACK` alert downstream.

### Multi-Signal Correlation Test

Combine two tests that fire within the correlation window:

```bash
# Terminal 1 — trigger Falco alert
docker exec -it node1 bash

# Terminal 2 — connect unexpected network within 120s
docker network connect always-on-security_storage-net node1

# → Multi-signal correlation: FALCO_ALERT + UNEXPECTED_NETWORK_ATTACH
#   If NETWORK_THREAT also fires from Suricata: 3.0× multiplier
```

---

## 8. Removed Components

The following were intentionally removed as part of the infrastructure-centric refactor:

| Component | Reason |
|---|---|
| **Tenant FIM** (`/etc/passwd`, `/etc/hosts`, `/etc/ssh/sshd_config` monitoring) | Production HPC providers do not hash customer-owned files. Violates workload ownership. The platform monitors infrastructure state, not customer data. |
| **`generate_baseline.py`** | Generated hashes of tenant files. Replaced by `capture_approved_images.py` and `capture_runtime_baseline.py` which capture infrastructure state only. |
| **`config_hashes.yaml`** | Stored SHA-256 of tenant config files. Replaced by `approved_images.yaml` and `runtime_baseline.yaml`. |
| **`process_policy.yaml`** | Process name denylist. Process names are trivially spoofable — `cp malware python`, `cp malware nginx`. The detector is ineffective against any informed attacker. Replaced by Falco kernel-level detection. |
| **Process name denylist detection** in `cluster_observer.py` | Same reason as above. `container.top()` still runs for process count telemetry but process names are no longer checked against a denylist. |
| **FIM rules** in `rules.yaml` (`FIM_CONFIG_TAMPER`, `FIM_FILE_MODIFIED`) | No longer generated. |
| **FIM decay hold** in `scoring.py` | FIM no longer exists. Replaced by image and drift event scoring. |
| **FIM columns** in dashboard | Replaced by image/drift/Falco counters. |

---

## 9. Known Gaps

| Issue | Category | Notes |
|---|---|---|
| `HMAC_SECRET` passed as plain env var | Secret management | Should migrate to Docker secrets or a vault |
| Base images use floating tags | Supply chain | Should pin to image digest |
| Falco uses `privileged: true` + `pid: host` | Attack surface | Required for kernel-level instrumentation; acceptable in Infrastructure Zone |
| `security-monitor` requires `privileged: true` | Attack surface | Required for Suricata/Zeek raw packet capture; Infrastructure Zone only |
| Host Observer polls every 5s | Detection latency | Near-real-time; not kernel-event-driven (that role now belongs to Falco) |
| `approved_images.yaml` has empty digests by default | Image attestation | Must be populated after first build with `capture_approved_images.py` |
| Falco uses `falco-no-driver` image | Kernel module | The eBPF driver approach requires kernel headers; `falco-no-driver` uses syscall fallback |
| Docker socket proxy still needed on Falco | Architecture | Falco mounts the raw socket directly for container metadata enrichment; this is a known Falco requirement |
