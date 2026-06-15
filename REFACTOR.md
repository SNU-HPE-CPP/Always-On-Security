# Requirements Document

## Introduction

The Always-On-Security repository currently implements a demo-style HPC security platform where
security logic (process inspection, process kill, FIM with inline restore, config tamper detection,
SSH lateral-movement scanning, and attack simulation) executes **inside** tenant node containers
that run as root. This produces an architecture where the trust boundary is inverted: tenant
workloads share a privilege context with the security enforcement layer, Docker socket access is
mislocated, and enforcement actions are performed from within the container being monitored.

This refactoring re-aligns the platform with production HPC security principles as practised in
HPE/SGI clusters, Slurm-managed environments, and air-gapped compute sites. The target state is:

- Tenant containers contain **only** workloads — no security agents, no root requirements,
  no psutil scanning, no inotify hooks, no inline kill or file-restore logic.
- Monitoring is performed **externally** by the `security-monitor`, `controller`, and
  `risk_engine` services acting on observable cluster signals (Docker events, network traffic,
  Zeek/Suricata output, telemetry from a privileged host-level observer).
- Enforcement is performed **centrally** — pause container, stop container, quarantine network
  (iptables), isolate node — with no process-level intervention inside tenant containers.
- `security-monitor` evolves from a passive Suricata/Zeek runner into an active multi-module
  security observer: `docker_collector`, `network_collector`, `threat_correlator`,
  `event_forwarder`, and `policy_engine`.

The environment is a monolithic HPC cluster: air-gapped, centrally administered, no internet
connectivity, no Kubernetes, no public cloud, change-controlled software supply chain.

---

## Glossary

- **Tenant_Container**: A Docker container running a user workload (currently `node1`–`node4`).
  Tenant containers are untrusted; they must not contain security agents or elevated privileges.
- **Security_Monitor**: The container responsible for passive and active external observation of
  the cluster. Runs Suricata, Zeek, and new Python-based collection modules.
- **Controller**: The ZeroMQ message forwarder and first security gate. Validates, stamps, and
  forwards all telemetry to the Risk_Engine.
- **Risk_Engine**: The central processing and remediation orchestrator. Scores events, runs threat
  detectors, and dispatches enforcement actions via the Docker API.
- **Host_Observer**: A privileged, host-level service (or privileged sidecar container) that
  inspects the Docker runtime, host process table, host network state, and container metadata
  **externally** — without running inside any tenant container.
- **Docker_Collector**: A new module inside Security_Monitor that subscribes to the Docker event
  stream to observe container lifecycle events from outside tenant boundaries.
- **Network_Collector**: A new module inside Security_Monitor that tails Suricata EVE JSON and
  Zeek notice logs and converts them into structured telemetry events.
- **Threat_Correlator**: A new module inside Security_Monitor that joins Docker events with
  network signals to produce correlated threat indicators.
- **Event_Forwarder**: A new module inside Security_Monitor that transmits signed events to the
  Controller over ZeroMQ, replacing the current node-agent send path.
- **Policy_Engine**: A new module inside Security_Monitor (or Risk_Engine) that evaluates
  enforcement decisions independently of cumulative score accumulation for critical signals.
- **Cluster_Observer**: A privileged host-level service that produces container resource metrics
  (CPU, memory, process count) by reading cgroup statistics or Docker stats — not by running
  psutil inside the tenant container.
- **Trust_Boundary**: The architectural line separating infrastructure-owned (trusted) services
  from tenant-owned (untrusted) containers.
- **Enforcement_Layer**: The set of enforcement actions available to the system: pause container,
  stop container, quarantine network (iptables DROP), isolate node (remove from cluster networks).
- **Zeek**: Network traffic analyser running in Security_Monitor, producing conn.log and
  notice.log for baseline deviation and lateral movement detection.
- **Suricata**: Signature-based NIDS running in Security_Monitor, producing EVE JSON alerts for
  known attack patterns, port scans, and protocol anomalies.
- **HMAC_Secret**: The shared HMAC-SHA256 key used to authenticate telemetry messages between
  infrastructure components. Never accessible to Tenant_Containers.
- **Golden_Copy**: The verified-good byte content of a monitored file, captured at service
  startup and used for auto-restore. Owned by the Host_Observer, not by tenant containers.
- **Denylist**: The list of forbidden process names (`nmap`, `hydra`, `netcat`, etc.) defined in
  `process_policy.yaml`.
- **Allowlist**: The set of approved node identities defined in `allowlist.yaml`.
- **Risk_Score**: The cumulative weighted score maintained per node by the Risk_Engine,
  decaying over time and triggering enforcement at defined thresholds.
- **Bucket**: The routing category assigned to a scoring decision: `silent`, `auto`, `human`,
  or `quarantine`.
- **EVE_JSON**: The structured JSON log format produced by Suricata for alert and flow records.

---

## Requirements

---

### Requirement 1: Current-State Assessment

**User Story:** As an HPC security administrator, I want a complete assessment of the existing
architecture's trust boundaries, privilege model, and attack surface, so that I understand every
specific problem that must be corrected before production deployment.

#### Acceptance Criteria

1. THE Assessment SHALL identify every location in the codebase where security logic executes
   inside a Tenant_Container, including: `security_collector.py`, `agent.py` FIM threads,
   `psutil` calls inside `node_agent/`, and inline process-kill and file-restore operations.

2. THE Assessment SHALL classify each identified finding by severity (CRITICAL / HIGH / MEDIUM /
   LOW), by risk category (Trust_Boundary_Violation / Privilege_Escalation / Attack_Surface /
   Demo_Only_Pattern), and by a production-suitability determination (Acceptable / Must_Fix /
   Must_Remove).

3. THE Assessment SHALL document every root-privilege dependency in `node_agent/Dockerfile` and
   `security_monitor/Dockerfile`, including the explicit justification comment already present
   in `node_agent/Dockerfile` (REC-01 process kill, REC-02 golden-copy restore, FIM chmod).

4. THE Assessment SHALL identify every location where the Docker socket (`/var/run/docker.sock`)
   is mounted, the container that holds the mount, and whether that mount is necessary and
   correctly scoped to infrastructure-owned services only.

5. THE Assessment SHALL document the six security checks in `controller/controller.py` (HMAC
   verification, rogue node detection, replay guard, flood guard, impersonation detection,
   duplicate ID detection) and classify each as: correctly placed in infrastructure (Compliant)
   or misplaced (Non_Compliant).

6. THE Assessment SHALL identify the attack surface created by `agent.py`'s built-in threat
   simulator (attack stages 1–5 that modify `/etc/hosts`, chmod `/etc/passwd`, delete
   `/etc/ssh/sshd_config`, and simulate hydra/process-explosion) and classify this as
   Demo_Only_Pattern with a Must_Remove determination.

7. THE Assessment SHALL document tenant visibility into monitoring: every telemetry field in
   the ZMQ payload sent from `node_agent/agent.py` that reveals which security checks are
   active, which processes triggered alerts, and which config files are monitored.

8. IF the Assessment identifies a finding where a tenant container can observe, predict, or
   interfere with the security monitoring logic, THEN THE Assessment SHALL classify that finding
   as CRITICAL severity.

---

### Requirement 2: HPC Industry Comparison

**User Story:** As an HPC security architect, I want a comparison of the current architecture
against real HPC security platforms (HPE HPC, Slurm, air-gapped cluster patterns), so that I
can identify which elements are realistic, which are demo artifacts, and which are production
anti-patterns.

#### Acceptance Criteria

1. THE Comparison SHALL evaluate the current architecture against HPE HPC / SGI cluster security
   practice on four dimensions: network segmentation model, enforcement mechanism model,
   monitoring placement model, and trust boundary model.

2. THE Comparison SHALL classify each architectural element as one of:
   Realistic_HPC_Pattern / Demo_Artifact / Production_Anti_Pattern / Kubernetes_Pattern.

3. THE Comparison SHALL identify the following specific elements and assign them a classification:
   - Security logic inside tenant containers (`security_collector.py`, FIM in `agent.py`)
   - Process kill from within the monitored container (`psutil.kill` in `security_collector.py`)
   - File restore from within the monitored container (golden-copy write in `agent.py`)
   - External Docker event monitoring (`docker_collector` — future state)
   - Network monitoring by a dedicated Security_Monitor container on all segments
   - Centralized enforcement via Docker API from Risk_Engine
   - Host-side iptables segment enforcement (`enforce_segment_iptables.sh`)
   - HMAC-signed telemetry between infrastructure components
   - Cumulative risk scoring with decay (`scoring.py`)
   - ZeroMQ message bus between node agents and controller

4. WHEN the Comparison identifies a Kubernetes_Pattern, THE Comparison SHALL document the
   specific reason it is not applicable to a monolithic HPC cluster with Docker Compose
   orchestration and no Kubernetes control plane.

5. THE Comparison SHALL identify realistic elements that already exist in the current codebase
   and are worth retaining in the refactored architecture, including Zeek conn.log analysis,
   Suricata signature-based NIDS, iptables segment boundaries, HMAC telemetry authentication,
   replay and flood guards, and Docker API-based enforcement.

---

### Requirement 3: Future-State Architecture

**User Story:** As an HPC security architect, I want a complete description of the target
architecture with clear component boundaries, data flows, and trust model, so that the
refactored system can be implemented without ambiguity.

#### Acceptance Criteria

1. THE Architecture SHALL define two trust zones: the Infrastructure_Zone (Security_Monitor,
   Controller, Risk_Engine, Host_Observer, Dashboard) and the Workload_Zone (Tenant_Containers).
   No component from the Workload_Zone SHALL have access to Infrastructure_Zone internals.

2. THE Architecture SHALL specify that Tenant_Containers contain only user workloads, with no
   security agents, no psutil imports, no inotify watches, no ZMQ sockets, no HMAC secret
   access, and no root or CAP_SYS_PTRACE capabilities.

3. THE Architecture SHALL define the Security_Monitor as composed of five modules:
   - `docker_collector.py` — subscribes to Docker event stream via Docker SDK
   - `network_collector.py` — tails Suricata EVE JSON and Zeek notice logs
   - `threat_correlator.py` — joins Docker events with network signals
   - `event_forwarder.py` — signs and transmits correlated events to Controller via ZeroMQ
   - `policy_engine.py` — evaluates fast-path enforcement for critical signals

4. THE Architecture SHALL specify that the Host_Observer (Cluster_Observer) produces container
   resource metrics (CPU, memory, process count) by reading Docker stats or cgroup accounting
   externally, without mounting any filesystem path inside Tenant_Containers.

5. THE Architecture SHALL include a complete architecture diagram showing all components,
   network segments (compute-net, storage-net, mgmt-net), data flows (ZMQ, Docker API,
   iptables, Suricata/Zeek log paths), and trust boundaries.

6. THE Architecture SHALL specify that the HMAC_Secret is accessible only to
   Infrastructure_Zone components (Security_Monitor event_forwarder, Controller, Risk_Engine)
   and is never passed to Tenant_Containers as an environment variable.

7. WHEN a threat is detected, THE Enforcement_Layer SHALL execute one or more of: pause
   container, stop container, apply iptables DROP for the container's network interface,
   or remove the container from cluster networks. THE Enforcement_Layer SHALL NOT execute
   process-level interventions (kill, chmod, file write) inside Tenant_Containers.

8. THE Architecture SHALL define the data flow for container resource telemetry: Host_Observer
   collects metrics externally → signs and sends to Controller → Controller forwards to
   Risk_Engine → Risk_Engine scores and routes to Enforcement_Layer.

---

### Requirement 4: Component Migration Matrix

**User Story:** As a developer implementing the refactor, I want an explicit mapping of every
significant file in the current codebase to its future-state fate, so that no code is orphaned
or accidentally retained.

#### Acceptance Criteria

1. THE Migration_Matrix SHALL account for every significant source file in the repository,
   classified by action: Keep / Delete / Rewrite / Merge / Split / Move.

2. THE Migration_Matrix SHALL cover at minimum the following files:
   `node_agent/agent.py`, `node_agent/security_collector.py`, `node_agent/secure_messenger.py`,
   `node_agent/Dockerfile`, `node_agent/fim_config.yaml`,
   `controller/controller.py`, `controller/secure_messenger.py`,
   `risk_engine/engine.py`, `risk_engine/pipeline.py`, `risk_engine/router.py`,
   `risk_engine/rules.py`, `risk_engine/scoring.py`, `risk_engine/correlation.py`,
   `risk_engine/enrichment.py`, `risk_engine/store.py`, `risk_engine/threat_detector.py`,
   `risk_engine/alert_manager.py`,
   `risk_engine/config/allowlist.yaml`, `risk_engine/config/process_policy.yaml`,
   `risk_engine/config/rules.yaml`, `risk_engine/config/thresholds.yaml`,
   `security_monitor/Dockerfile`, `security_monitor/start.sh`,
   `security_monitor/suricata/hpc-scan.rules`, `security_monitor/suricata/suricata.yaml`,
   `scripts/beaconing_detector.py`, `scripts/compute_baseline.py`,
   `scripts/enforce_segment_iptables.sh`,
   `docker-compose.yml`, `generate_baseline.py`.

3. FOR EACH file in the Migration_Matrix, THE Matrix SHALL specify: the current component that
   owns it, the future component that will own it, the action (Keep/Delete/Rewrite/Merge/Split/
   Move), the rationale, and the estimated effort (XS / S / M / L / XL).

4. THE Migration_Matrix SHALL identify files that can be deleted outright with no replacement
   (dead code, demo-only patterns), including: the built-in attack simulator in `agent.py`
   (Stages 1–5), the inline golden-copy file-restore logic in `agent.py`'s `fim_monitor()`,
   and the process-kill logic in `security_collector.py`.

5. THE Migration_Matrix SHALL identify new files that must be created that have no current
   equivalent, including: `security_monitor/docker_collector.py`,
   `security_monitor/network_collector.py`, `security_monitor/threat_correlator.py`,
   `security_monitor/event_forwarder.py`, `security_monitor/policy_engine.py`,
   and any new Host_Observer service.

---

### Requirement 5: Root-Elimination Strategy

**User Story:** As an HPC security administrator, I want every root-privilege dependency in
all container Dockerfiles identified and a concrete plan to eliminate or relocate each one,
so that tenant-adjacent containers do not run as root.

#### Acceptance Criteria

1. THE Strategy SHALL enumerate every reason `node_agent/Dockerfile` requires root, sourced
   directly from the existing justification comment: (a) `psutil.Process(pid).kill()` for
   process kill enforcement, (b) `open('/etc/passwd', 'wb').write(golden)` for config restore,
   (c) `os.chmod('/etc/passwd', 0o644)` for permission restore.

2. FOR EACH root dependency in `node_agent`, THE Strategy SHALL specify the relocation target:
   the logic moves to the Host_Observer or Security_Monitor running with appropriate Linux
   capabilities, and the Tenant_Container drops to a non-root unprivileged user.

3. THE Strategy SHALL confirm that `controller`, `dashboard`, `risk_engine`, and `wazuh`
   Dockerfiles have already been migrated to non-root `appuser` as documented in
   `NON_ROOT_USER_ANALYSIS.md`, and classify these as Compliant.

4. THE Strategy SHALL document that `security_monitor` requires `privileged: true`,
   `CAP_NET_ADMIN`, and `CAP_NET_RAW` for Suricata/Zeek packet capture, and classify this
   as Acceptable because the container is Infrastructure_Zone, not Workload_Zone.

5. THE Strategy SHALL specify that after refactoring, no Tenant_Container SHALL have any
   of the following: root user, `privileged: true`, `CAP_SYS_PTRACE`, `CAP_KILL`,
   `CAP_DAC_OVERRIDE`, Docker socket mount, or access to host PID or network namespace.

6. THE Strategy SHALL identify the Linux capability set required by the Host_Observer:
   `CAP_KILL` (for process enforcement if retained externally), `CAP_DAC_READ_SEARCH`
   (for reading protected config files), and `CAP_NET_ADMIN` (for iptables enforcement),
   and specify that only the Host_Observer and Security_Monitor hold these capabilities.

---

### Requirement 6: Security-Monitor Evolution Plan

**User Story:** As a developer, I want a detailed specification of each new module to be added
to the Security_Monitor service, so that I can implement them independently as reviewable units.

#### Acceptance Criteria

1. THE Plan SHALL specify `docker_collector.py` with the following responsibilities:
   subscribes to the Docker daemon event stream using `docker.APIClient.events()`,
   parses container start/stop/die/pause/kill/exec events, emits structured telemetry records
   including container name, image, event type, exit code, and timestamp.

2. THE Plan SHALL specify `network_collector.py` with the following responsibilities:
   tails `/var/log/suricata/eve.json` using inotify or polling, tails Zeek `notice.log` and
   `conn.log`, parses each record into a normalised event dict, filters for HPC-relevant
   alert categories (port scans, protocol abuse, lateral movement, beaconing), and emits
   structured telemetry records.

3. THE Plan SHALL specify `threat_correlator.py` with the following responsibilities:
   receives event records from both `docker_collector` and `network_collector` via an internal
   queue, correlates Docker lifecycle events with near-simultaneous network alerts on the same
   container IP, assigns a correlation confidence level, and emits correlated threat records.

4. THE Plan SHALL specify `event_forwarder.py` with the following responsibilities:
   receives correlated threat records from `threat_correlator`, signs each record with
   HMAC-SHA256 using the shared HMAC_Secret, assigns a sequence number, and transmits the
   signed record to the Controller via ZeroMQ PUSH socket, reusing the existing
   `secure_messenger.py` signing protocol.

5. THE Plan SHALL specify `policy_engine.py` with the following responsibilities:
   evaluates incoming correlated threat records against a policy table (loaded from YAML),
   determines whether a fast-path enforcement action is required (bypassing score accumulation),
   calls the Risk_Engine's enforcement API or directly invokes Docker API actions for
   CRITICAL-severity signals, and logs every enforcement decision with a structured audit record.

6. FOR ALL new modules, THE Plan SHALL specify: input interface (queue, file path, ZMQ socket),
   output interface, configuration file or environment variable dependencies, required Python
   stdlib or existing-repo imports only (no new third-party dependencies beyond what is already
   in the repo), and failure behavior (log error, sleep, retry — do not crash the container).

7. THE Plan SHALL specify that all five new modules run as threads or processes within the
   single `security-monitor` container, coordinated by a `main.py` supervisor, replacing the
   current `start.sh` bash launcher with a Python process manager.

---

### Requirement 7: Detection Coverage Analysis

**User Story:** As an HPC security engineer, I want each threat category mapped to the
architectural layer that should own detection, with a justification, so that there is no
detection logic in the wrong layer and no coverage gap.

#### Acceptance Criteria

1. THE Analysis SHALL cover the following threat categories at minimum:
   CPU/memory/process-count resource anomalies, suspicious process names (denylist),
   config file tampering (hash mismatch), lateral movement (unexpected SSH connections),
   replay attacks (duplicate msg_id or stale timestamp), rogue nodes (unknown machine_id),
   telemetry tampering (HMAC failure), message flooding (rate excess), silent node (heartbeat
   timeout), network threats (port scan, protocol abuse, unexpected egress/listener),
   beaconing (low-variance periodic traffic), coordinated multi-node attacks (cross-node
   correlation), and container privilege escalation attempts.

2. FOR EACH threat category, THE Analysis SHALL specify: which layer owns detection
   (Tenant_Workload / Security_Monitor / Controller / Risk_Engine / Host_Observer),
   which layer owns enforcement, the detection mechanism, and the reason the detection
   cannot or should not be performed from inside the Tenant_Container.

3. THE Analysis SHALL confirm that the following detections move OUT of Tenant_Containers:
   process-name scanning (moves to Host_Observer via external `/proc` inspection or
   Docker exec with controlled scope), config file hash checking (moves to Host_Observer),
   psutil network connection inspection (moves to Security_Monitor network_collector and
   Zeek/Suricata), and inotify file watches on `/etc/hosts`, `/etc/passwd`,
   `/etc/ssh/sshd_config` (moves to Host_Observer).

4. THE Analysis SHALL confirm that the following detections remain correctly placed and require
   no migration: HMAC verification (Controller), replay guard (Controller), flood guard
   (Controller), rogue node detection (Controller + Risk_Engine), cumulative risk scoring
   (Risk_Engine), cross-node correlation (Risk_Engine), Docker API enforcement (Risk_Engine),
   network signature detection (Security_Monitor/Suricata), network behaviour analysis
   (Security_Monitor/Zeek), and beaconing detection (`scripts/beaconing_detector.py`).

5. WHEN a detection previously performed inside a Tenant_Container has no external equivalent,
   THE Analysis SHALL specify a concrete replacement mechanism using only permitted tooling:
   Linux-native, Docker-native, Python stdlib, existing repo components, or derived from
   existing Zeek/Suricata outputs.

---

### Requirement 8: Enforcement Review

**User Story:** As an HPC security administrator, I want a review of all current enforcement
actions and a specification of the target enforcement model, so that the refactored system
enforces at the container and network level without any in-tenant intervention.

#### Acceptance Criteria

1. THE Review SHALL document all current enforcement actions and classify each as:
   Correct_Placement / Must_Relocate / Must_Remove:
   - `psutil.Process.kill()` in `security_collector.py` — Must_Relocate (to Host_Observer)
     or Must_Remove (if the container trust model makes in-container kill unnecessary)
   - Golden-copy file restore (`open('/etc/passwd', 'wb')`) in `agent.py` — Must_Relocate
     (to Host_Observer) or Must_Remove (tenant containers should not contain these files)
   - `os.chmod()` restore in `agent.py` — Must_Relocate or Must_Remove (same rationale)
   - `container.pause()` in `router.py` — Correct_Placement (infrastructure layer)
   - `container.stop()` in `router.py` — Correct_Placement (infrastructure layer)
   - Wazuh UDP alert in `router.py` — Correct_Placement (infrastructure layer)

2. THE Review SHALL specify the complete target enforcement repertoire:
   (a) Pause container — `container.pause()` via Docker API, existing in `router.py`
   (b) Stop container — `container.stop()` via Docker API, existing in `router.py`
   (c) Quarantine network — iptables DROP rules for the container's source IP on all segments,
       implemented in a new `network_isolator.py` module in Risk_Engine or Security_Monitor
   (d) Isolate node — disconnect container from compute-net and storage-net while preserving
       mgmt-net connectivity for forensic access, via Docker network disconnect API

3. THE Review SHALL specify that enforcement actions (c) and (d) require `CAP_NET_ADMIN` on
   the enforcing container, document which container holds that capability in the current
   `docker-compose.yml`, and specify any compose changes needed to grant it correctly.

4. THE Review SHALL confirm that after refactoring no enforcement action SHALL modify files,
   kill processes, or alter state **inside** any Tenant_Container, and SHALL document this
   as the central invariant of the production enforcement model.

5. WHEN a CRITICAL-severity alert is emitted (ROGUE_NODE, NODE_IMPERSONATION,
   TELEMETRY_TAMPER), THE Policy_Engine SHALL trigger an enforcement action within one
   risk-engine processing cycle without waiting for cumulative score to reach the quarantine
   threshold, reusing the fast-path pattern described in REC-05 of `SECURITY_PROJECT_PLAN.txt`.

---

### Requirement 9: Docker Architecture Review

**User Story:** As a DevSecOps engineer, I want a review of all container privilege settings,
volume mounts, capabilities, and network configuration in `docker-compose.yml`, with specific
hardening recommendations, so that the compose file reflects the principle of least privilege.

#### Acceptance Criteria

1. THE Review SHALL evaluate every service in `docker-compose.yml` against the following
   criteria: user (root vs non-root), capabilities added, privileged flag, volume mounts
   (necessity and scope), network attachments (principle of least segment access), and
   environment variables (secrets exposure).

2. THE Review SHALL confirm that the HMAC_Secret is passed only to Controller and
   Event_Forwarder (Security_Monitor), and SHALL flag the current pattern of passing
   `HMAC_SECRET=${HMAC_SECRET}` to all four `node1`–`node4` services as a
   Trust_Boundary_Violation requiring immediate correction.

3. THE Review SHALL specify hardened compose entries for each service, including:
   the correct `user` or `USER` directive, the minimum required `cap_add` set,
   removal of any unnecessary volume mounts, correct `networks` attachment per zone,
   and `read_only: true` where feasible.

4. THE Review SHALL specify that Tenant_Containers (node1–node4 in the refactored compose)
   SHALL have no environment variables exposing security configuration, no config volume
   mounts from `risk_engine/config/`, no ZMQ ports or addresses for the security bus,
   and SHALL run as a non-root user.

5. THE Review SHALL document that `security-monitor` legitimately requires `privileged: true`,
   `CAP_NET_ADMIN`, and `CAP_NET_RAW` for Suricata/Zeek packet capture, and that this is
   correctly scoped to the Infrastructure_Zone.

6. THE Review SHALL identify that the Docker socket mount (`/var/run/docker.sock`) in
   `risk-engine` is correctly placed in the Infrastructure_Zone and SHALL specify the
   minimal surface hardening: read-only socket mount where sufficient, or a Docker socket
   proxy (`docker-socket-proxy`) that restricts the socket to specific API calls only.

---

### Requirement 10: Refactoring Roadmap

**User Story:** As a developer or team lead, I want a phased refactoring roadmap with concrete
file-level tasks, effort estimates, and risk ratings, so that the refactor can be executed
incrementally without breaking the working demo state.

#### Acceptance Criteria

1. THE Roadmap SHALL define five phases:
   - Phase 0: Quick Wins (effort < 1 day per task)
   - Phase 1: Architecture Cleanup (remove demo artifacts, fix trust boundary violations)
   - Phase 2: Monitoring Migration (move detection out of tenant containers)
   - Phase 3: Security-Monitor Expansion (implement new modules)
   - Phase 4: Production-Style HPC Alignment (full trust model, hardened compose)

2. FOR EACH phase, THE Roadmap SHALL specify: the list of files modified / removed / added,
   the estimated effort (person-days), the risk rating (Low / Medium / High), the testing
   requirements, and the rollback strategy.

3. Phase 0 tasks SHALL include at minimum:
   - Remove HMAC_Secret from all Tenant_Container environment blocks in `docker-compose.yml`
   - Remove `PROCESS_POLICY_PATH` and `CONFIG_HASHES_PATH` mounts from node1–node4
   - Remove the attack simulator (Stages 1–5) from `agent.py`
   - Remove inline golden-copy restore from `agent.py` FIM thread
   - Remove process-kill logic from `security_collector.py`
   - Add `read_only: true` to config volume mounts already present

4. Phase 1 tasks SHALL include at minimum:
   - Rewrite `agent.py` to contain only workload simulation and metric collection
     (CPU/memory/process count over ZMQ) with no security detection logic
   - Remove `security_collector.py` from `node_agent/` entirely
   - Refactor `node_agent/Dockerfile` to run as non-root `appuser`
   - Update `controller.py` to remove any assumption about security fields
     originating from node agents

5. Phase 2 tasks SHALL include at minimum:
   - Implement `cluster_observer.py` (Host_Observer) that reads container metrics
     externally via Docker stats API
   - Migrate config-tamper detection to Host_Observer via bind-mount of host config paths
   - Migrate process denylist checking to Host_Observer via Docker exec or `/proc` inspection

6. Phase 3 tasks SHALL include at minimum:
   - Implement `docker_collector.py`, `network_collector.py`, `threat_correlator.py`,
     `event_forwarder.py`, and `policy_engine.py` in `security_monitor/`
   - Replace `start.sh` with a Python `main.py` process supervisor in `security_monitor/`
   - Update `security_monitor/Dockerfile` to include Python dependencies

7. Phase 4 tasks SHALL include at minimum:
   - Apply full hardened `docker-compose.yml` with least-privilege node definitions
   - Implement `network_isolator.py` for iptables-based container quarantine
   - Implement Docker network disconnect for node isolation
   - Validate that no Tenant_Container has access to Infrastructure_Zone configuration

---

### Requirement 11: AI Implementation Plan

**User Story:** As a developer using coding agents to assist implementation, I want each
refactoring task decomposed into AI-suitable units — independent, PR-sized, low-risk first —
so that agents can implement them without creating integration conflicts.

#### Acceptance Criteria

1. THE Plan SHALL decompose the refactoring into tasks where each task: modifies at most
   five files, has a single clear objective, has defined acceptance criteria, and can be
   reviewed independently as a pull request.

2. THE Plan SHALL order tasks from lowest to highest risk, where risk is defined as:
   probability of breaking the currently working demo × difficulty of rollback.

3. THE Plan SHALL tag each task with a risk level (Safe / Review_Required / High_Risk) and
   a dependency list (which prior tasks must be complete before this task starts).

4. FOR EACH task, THE Plan SHALL specify: the task objective, the files affected
   (modify / create / delete), the concrete expected outcome (what changes in behaviour),
   and the test to verify completion.

5. Tasks classified as Safe (no behaviour change, no new dependencies) SHALL include:
   - Remove attack simulator from `agent.py`
   - Remove HMAC_Secret env var from node service definitions in compose
   - Remove process-kill loop from `security_collector.py`
   - Remove golden-copy restore logic from `agent.py` FIM thread
   - Add `read_only: true` to all config volume mounts

6. Tasks classified as Review_Required (behaviour change but limited blast radius) SHALL
   include: implementing `cluster_observer.py`, adding `docker_collector.py`,
   rewriting `agent.py` to workload-only, refactoring `node_agent/Dockerfile` to non-root.

7. Tasks classified as High_Risk (system-wide integration changes) SHALL include:
   implementing `policy_engine.py` with fast-path enforcement, implementing
   `network_isolator.py` with iptables enforcement, and replacing `start.sh` with
   the Python supervisor in `security_monitor/`.

---

### Requirement 12: Code Generation Preparation

**User Story:** As a developer preparing for AI-assisted code generation, I want an inventory
of dead code, duplicated logic, responsibilities in the wrong service, and simplification
opportunities, so that the code generation baseline is clean and unambiguous.

#### Acceptance Criteria

1. THE Inventory SHALL identify all dead code in the current repository: code that executes
   but produces no effect useful to the refactored architecture. This includes: the threat
   simulator in `agent.py` (Stages 1–5 with `under_attack` / `attack_stage` state machine),
   the `job_worker()` thread and associated `current_job` / `job_lock` state, `FAILED_LOGIN_USERS`
   and `PRIV_ESC_USERS` lists, and `failed_login_count` / `privilege_escalation_attempts` fields.

2. THE Inventory SHALL identify all duplicated logic that exists in two or more places in the
   current codebase: HMAC signing exists in both `node_agent/secure_messenger.py` and
   `controller/secure_messenger.py` (these are copies of the same module and should be a
   single shared library); rogue-node detection runs in both `controller.py` and
   `risk_engine/threat_detector.py` (the controller check is the correct location; the
   engine-level re-check is redundant redundancy); flood detection runs in both
   `controller.py` (FloodGuard) and `threat_detector.py` (`_detect_secondary_flood`).

3. THE Inventory SHALL identify responsibilities placed in the wrong service:
   - Config-hash tamper detection is in `node_agent/security_collector.py` — it belongs
     in the Host_Observer (infrastructure layer).
   - Process policy enforcement is in `node_agent/security_collector.py` — it belongs
     in the Host_Observer.
   - Lateral movement detection via `psutil.net_connections()` is in
     `node_agent/security_collector.py` — it belongs in Security_Monitor network_collector.
   - FIM inotify watches are in `node_agent/agent.py` — they belong in Host_Observer.
   - Golden-copy file restore is in `node_agent/agent.py` — it belongs in Host_Observer
     or should be removed if the target model prohibits modifying files inside any container.

4. THE Inventory SHALL identify simplification opportunities:
   - `agent.py` can be reduced from ~500 lines with 4 threads to ~100 lines with 1 thread
     once all security logic is removed and only workload metric collection remains.
   - `security_collector.py` can be deleted entirely; its legitimate detection logic
     migrates to Host_Observer and Security_Monitor.
   - `fim_config.yaml` can be deleted from `node_agent/`; FIM configuration moves to
     Host_Observer configuration.
   - `generate_baseline.py` can be moved to Host_Observer tooling.

5. THE Inventory SHALL confirm that the following modules require NO changes to their core
   logic during refactoring (they are already correctly placed): `controller/controller.py`
   (all six security checks are correctly in the infrastructure layer), `risk_engine/scoring.py`,
   `risk_engine/correlation.py`, `risk_engine/pipeline.py`, `risk_engine/rules.py`,
   `risk_engine/alert_manager.py`, `risk_engine/threat_detector.py` (post-removal of the
   secondary duplicate checks noted above), `scripts/beaconing_detector.py`,
   `scripts/enforce_segment_iptables.sh`, and `security_monitor/suricata/hpc-scan.rules`.

6. WHEN the code generation agent processes a file marked as Simplify, THE Inventory SHALL
   provide the specific lines or functions to remove, the residual interface that must be
   preserved (ZMQ send format, field names consumed downstream), and the regression test
   that confirms the downstream consumer still functions correctly after simplification.

