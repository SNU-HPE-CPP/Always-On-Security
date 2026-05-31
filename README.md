# Always-On Security System

Distributed security monitoring and automated remediation system for Monolithic HPC environments. Built with Docker, Python, ZeroMQ, SQLite, and Flask.

---

## Architecture

```
node1 ─┐
node2 ─┤──PUSH──► controller:5555 ──PUSH──► risk-engine:5556 ──► SQLite (/data/events.db)
node3 ─┤                                          │
node4 ─┘                                          ├── Docker.stop()  (quarantine)
                                                  └── bucket routing (auto / human stubs)
                                                              │
                                                         dashboard:8000
                                                         (read-only Flask)
```

**7 containers** — `controller`, `risk-engine`, `dashboard`, `node1`–`node4`.

| Service | Role |
|---------|------|
| `node_agent` (×4) | Collect CPU/memory/process telemetry via psutil every 5s, PUSH JSON to controller |
| `controller` | Thin ZMQ relay — adds monotonic offset + timestamp, forwards to risk-engine. State: `/data/controller.offset` |
| `risk-engine` | 5-step enrichment pipeline, weighted scoring, cross-node correlation, bucket routing, quarantine |
| `dashboard` | Flask UI at `localhost:8000` — last 20 events + per-bucket counts |

---

## Risk Engine (Layer 3)

### Detection Rules (`risk_engine/config/rules.yaml`)

| Rule ID | Trigger | Severity | Blast Radius |
|---------|---------|----------|--------------|
| `HIGH_CPU` | `"CPU"` in reasons | 10 | 5 |
| `HIGH_MEMORY` | `"memory"` in reasons | 10 | 5 |
| `PROCESS_COUNT` | `"Too many"` in reasons | 15 | 10 |
| `SUSPICIOUS_PROCESS` | `"Suspicious process"` in reasons | 35 | 20 |

Rules are **hot-reloadable** — edit `rules.yaml` while the engine is running, no restart needed.

### Weighted Scoring Formula

```
event_score = severity × blast_radius × asset_criticality / 1000
cumulative  = persisted_node_score + event_score
```

`asset_criticality` per node from `node_criticality.yaml` (default 15, node4 = 30).

### Score Buckets (`thresholds.yaml`)

| Bucket | Range | Action |
|--------|-------|--------|
| `silent` | 0–30 | Log only |
| `auto` | 31–70 | Log + stub (Ansible deferred) |
| `human` | 71–100 | Log + stub (Mattermost deferred) |
| `quarantine` | > 100 | `container.stop()` via Docker SDK |

### Cross-Node Correlation

If 3+ distinct nodes hit the same rule within a 10-minute window, the event score is multiplied by **×1.5** and flagged as `CORRELATED` in the DB.

### Durability

- Node scores persisted to `node_scores` SQLite table — survive controller restart.
- Monotonic event offset committed atomically with each event — engine replays missed events on restart.

---

## Node Agent Detection Rules

| Condition | Reason string |
|-----------|--------------|
| CPU > 10% | `"High CPU usage detected"` |
| Memory > 50% | `"High memory usage detected"` |
| Process count > 300 | `"Too many running processes"` |
| Process name in `[nmap, hydra, nc, netcat, stress]` | `"Suspicious process detected: <name>"` |

---

## Quick Start

```bash
# Prerequisites: Docker Desktop running

git clone <repo-url>
cd Always-On-Security-

# Build and start all 7 containers
docker compose up --build -d

# Verify all containers are up
docker compose ps

# Open dashboard
open http://localhost:8000

# Tail all logs
docker compose logs -f

# Tail risk engine only
docker compose logs -f risk-engine

# Stop everything
docker compose down
```

---

## Generating Test Alerts

**High CPU** (triggers `HIGH_CPU` rule → +0.5 per event on default node):
```bash
docker exec -it node1 bash -c "yes > /dev/null &"
```

**Suspicious process** (triggers `SUSPICIOUS_PROCESS` → +17.5 on node4):
```bash
docker exec -it node4 bash -c "apt-get install -y nmap -qq && nmap localhost &"
```

**Query events directly**:
```bash
sqlite3 data/events.db \
  "SELECT node, bucket, weighted_score, correlated, matched_rules FROM events ORDER BY id DESC LIMIT 10;"
```

---

## Configuration

All config files live in `risk_engine/config/` and are bind-mounted read-only into the container. Edit them while the stack is running — rules reload automatically; threshold/criticality changes take effect on the next event.

| File | Purpose |
|------|---------|
| `rules.yaml` | Detection rules (id, match, severity, blast_radius) |
| `thresholds.yaml` | Bucket boundaries + correlation window/multiplier |
| `node_criticality.yaml` | Per-node asset criticality weights (0–30) |

---

## Database Schema

`/data/events.db` (SQLite, WAL mode):

| Table | Key columns |
|-------|------------|
| `events` | `timestamp, node, cpu_usage, memory_usage, process_count, event_type, reasons, risk_score, weighted_score, bucket, correlated, matched_rules` |
| `node_scores` | `node, cumulative_score, updated_at` |
| `engine_offset` | `last_committed` (replay cursor) |

---

## Known Gaps (PoC Scope)

See `ISSUES.md` for the full build tracker. Key deferred items:

- **Ansible orchestrator** — `auto` bucket currently logs a stub
- **Mattermost notifications** — `human` bucket currently logs a stub
- **PostgreSQL** — SQLite only (Layer 5)
- **auditd / Falco / AIDE** — no kernel-level detection (Layer 1)
- **OpenSCAP** — no compliance scanning
- **Vault / SPIRE** — no secrets or identity plane
- **CI/CD pipeline** — no `.github/workflows/`

---

## Project Structure

```
Always-On-Security-/
├── controller/          # Thin ZMQ relay
│   ├── controller.py
│   ├── Dockerfile
│   └── requirements.txt
├── risk_engine/         # Layer 3 scoring engine
│   ├── engine.py
│   ├── pipeline.py
│   ├── store.py
│   ├── enrichment.py
│   ├── correlation.py
│   ├── rules.py
│   ├── scoring.py
│   ├── router.py
│   ├── Dockerfile
│   ├── requirements.txt
│   └── config/
│       ├── rules.yaml
│       ├── thresholds.yaml
│       └── node_criticality.yaml
├── dashboard/           # Flask read-only UI
│   ├── app.py
│   ├── Dockerfile
│   ├── requirements.txt
│   └── templates/index.html
├── node_agent/          # psutil telemetry collector (×4)
│   ├── agent.py
│   └── Dockerfile
├── data/                # Shared SQLite volume
├── docker-compose.yml
└── ISSUES.md            # Build tracker
```
