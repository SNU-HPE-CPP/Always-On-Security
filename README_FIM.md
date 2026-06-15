# File Integrity Monitoring (FIM) Integration

This document describes the **File Integrity Monitoring (FIM)** feature implemented in this branch of the Always-On Security platform. It details what the feature is, how it works under the hood, and the tools and changes introduced to integrate it.

---

## 1. What It Does
File Integrity Monitoring (FIM) is a security control that detects unauthorized changes to critical files and directories. In this platform, FIM provides real-time visibility and threat detection for:
* **File Creation:** Detects when new files are created in watched directories.
* **File Modification:** Detects content changes by comparing the file's current SHA-256 hash against its established baseline.
* **File Deletion:** Detects when monitored files or files inside watched directories are deleted.
* **Permission & Ownership Changes:** Monitors attribute modifications (`chmod`/`chown`), flagging unsafe permission shifts (e.g., world-writable configurations).

---

## 2. Architecture & How It Works

The FIM integration is woven into the platform's multi-layered security architecture:

```
┌────────────────────────────────────────────────────────────────────────┐
│                              NODE AGENT                                │
│                                                                        │
│   ┌────────────────────────┐         ┌──────────────────────────────┐  │
│   │  fim_config.yaml       │         │  FIM Watcher Thread          │  │
│   │  - Critical files      │───────► │  - inotify event monitoring  │  │
│   │  - Watched directories │         │  - SHA-256 baseline hashing  │  │
│   └────────────────────────┘         └──────────────┬───────────────┘  │
└─────────────────────────────────────────────────────│──────────────────┘
                                                      │ ZMQ (:5555)
                                                      ▼
┌────────────────────────────────────────────────────────────────────────┐
│                              CONTROLLER                                │
│                                                                        │
│   - Receives FIM events                                                │
│   - Attaches monotonically increasing offsets                          │
│   - Forwards to Risk Engine                                            │
└─────────────────────────────────────────────────────┬──────────────────┘
                                                      │ ZMQ (:5556)
                                                      ▼
┌────────────────────────────────────────────────────────────────────────┐
│                             RISK ENGINE                                │
│                                                                        │
│   ┌────────────────────────┐         ┌──────────────────────────────┐  │
│   │  rules.yaml            │         │  Weighted Scorer & DB        │  │
│   │  - FIM Severity/Blast  │───────► │  - Holds decay for 5 minutes  │  │
│   │  - Map rules to scores │         │  - Persists FIM metadata     │  │
│   └────────────────────────┘         └──────────────┬───────────────┘  │
└─────────────────────────────────────────────────────│──────────────────┘
                                                      ▼
                                           SQLite (events.db)
```

### A. Initialization & Baseline Store
1. Upon start, the **Node Agent** reads the `fim_config.yaml` using the `load_fim_config()` function.
2. It ensures all specified watch directories exist, and pre-creates any missing critical files.
3. It recursively scans watched paths and computes initial baseline metadata (`sha256` hash for files under 50MB, file size, permissions, and owner/group).

### B. Filesystem Event Interception
1. The Node Agent's **FIM Monitor Thread** registers native OS watches on target directories using the Linux `inotify` API.
2. When a file operation occurs:
   * The event is debounced slightly (200ms sleep) to allow the filesystem operation to complete.
   * Current metadata is fetched and compared with the stored baseline.
   * If a modification, deletion, creation, or permission change is detected, a `FIM_EVENT` payload containing the file path and states is prepared.

### C. ZMQ Transport & Offset Stamping
* The FIM event is pushed over ZeroMQ (port 5555) to the **Controller**.
* The Controller assigns the event a sequential transaction offset and forwards it to the **Risk Engine** on ZeroMQ port 5556.

### D. Scoring & Decay Hold
* The **Risk Engine** maps the event reason to the matching rule in `rules.yaml`.
* The **WeightedScorer** updates the node's cumulative risk score according to the rule severity and asset criticality.
* **Risk Score Decay Hold:** FIM events are high-priority alerts. To prevent the score from decaying immediately, a **5-minute decay hold** is placed on the node. For 300 seconds, the automatic self-healing decay process is suspended for that node.

### E. Persistence & Visibility
* The event is persisted to the SQLite database `events.db` (`events` table). Additional schema fields store FIM specifics: `file_path`, `fim_event_type`, `sha256`, `file_size`, and `permissions`.
* The Flask **Dashboard** renders the active FIM events on the feed in real-time, showing paths and FIM event types (e.g., `FIM_FILE_MODIFIED`).

---

## 3. Libraries & Tools Used
* **`inotify-simple`**: A lightweight Python wrapper for Linux `inotify` APIs. It provides efficient, non-blocking kernel-level filesystem event observation without polling overhead.
* **`pyyaml`**: Used for parsing YAML configuration files (`fim_config.yaml` on Node Agents, and `rules.yaml` on the Risk Engine).
* **`hashlib`**: Computes SHA-256 integrity hashes.
* **`sqlite3`**: Manages event logging and state durability.
* **`pyzmq`**: Facilitates low-latency ZeroMQ message queuing.

---

## 4. Summary of Changes Made in this Branch

### Node Agent (`node_agent/`)
* **`Dockerfile`**: Added `inotify-simple` and `pyyaml` dependencies to the installation step.
* **`fim_config.yaml`**: Created a configuration file to declare critical paths to monitor.
* **`agent.py`**:
  * Implemented `fim_monitor` thread loop using `INotify`.
  * Added `get_file_metadata` baseline logic.
  * Augmented the **Threat Simulator** to trigger simulated FIM attacks during the multi-stage threat lifecycle:
    * *Stage 2*: Modifies `/etc/hosts` (triggers file modification FIM event).
    * *Stage 3*: Alters permissions of `/etc/passwd` to `0777` (triggers permission change FIM event).
    * *Stage 4*: Deletes `/etc/ssh/sshd_config` (triggers file deletion FIM event).

### Risk Engine (`risk_engine/`)
* **`store.py`**: Added database migration steps during schema initialization to inject FIM columns (`file_path`, `fim_event_type`, `sha256`, `file_size`, `permissions`) and updated `write_event()` to store them.
* **`scoring.py`**: Added the FIM-specific decay hold (`self.fim_hold_until`) to hold risk decay for 300 seconds following any `FIM_` rule match.
* **`config/rules.yaml`**: Defined five FIM rules with corresponding severities and blast radii:
  * `FIM_FILE_CREATED` (Severity: 40, Blast Radius: 35)
  * `FIM_FILE_MODIFIED` (Severity: 50, Blast Radius: 40)
  * `FIM_PERMISSION_CHANGED` (Severity: 60, Blast Radius: 45)
  * `FIM_FILE_DELETED` (Severity: 70, Blast Radius: 50)
  * `FIM_BASELINE_TAMPERING` (Severity: 90, Blast Radius: 60)

### Dashboard (`dashboard/`)
* **`templates/index.html`**: Added dedicated templating blocks to extract and display FIM event types and paths in the events feed.
