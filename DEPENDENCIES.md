# Open-Source Dependencies

All third-party tools, libraries, and frameworks used in Always-On Security.

---

## Table of Contents

1. [Security Tools](#1-security-tools)
2. [Container & Infrastructure Tools](#2-container--infrastructure-tools)
3. [Python Libraries — by Service](#3-python-libraries--by-service)
4. [Frontend Libraries](#4-frontend-libraries)
5. [CI/CD & Build-Time Security Tools](#5-cicd--build-time-security-tools)
6. [Python Standard Library Modules](#6-python-standard-library-modules)
7. [Quick-Reference Summary](#7-quick-reference-summary)

---

## 1. Security Tools

These are the core open-source security engines integrated into the platform.

### Falco
| | |
|---|---|
| **License** | Apache-2.0 |
| **Website** | https://falco.org |
| **Version used** | 0.44.1 (modern eBPF driver) |
| **How it runs** | Installed natively on the host; writes JSON events to `/var/log/falco/events.json` |
| **Used in** | `security_monitor/falco_collector.py` tails the output file |
| **Purpose** | Kernel-level syscall monitoring (via eBPF). Detects runtime threats inside containers from the host: reverse shells, privilege escalation attempts, container escape attempts, unexpected shell spawns. The `falco_collector` maps Falco rule names to internal threat types: `REVERSE_SHELL`, `CONTAINER_ESCAPE_ATTEMPT`, `PRIV_ESC_ATTEMPT`, `FALCO_ALERT`. |

### Suricata
| | |
|---|---|
| **License** | GPL-2.0 |
| **Website** | https://suricata.io |
| **Version used** | Installed from Ubuntu 22.04 apt (`suricata` package) |
| **How it runs** | Launched as a subprocess by `security_monitor/main.py`; captures on `eth0` |
| **Used in** | `security_monitor/network_collector.py` tails `/var/log/suricata/eve.json` |
| **Config** | `security_monitor/suricata/suricata.yaml`, `security_monitor/suricata/hpc-scan.rules`, `security_monitor/suricata/threshold.conf` |
| **Purpose** | Network Intrusion Detection System (NIDS). Performs deep-packet inspection on east-west cluster traffic. Custom HPC-specific signature rules (`hpc-scan.rules`) detect port scans, lateral movement, and anomalous flows. Emits alerts to `eve.json` (EVE JSON format) consumed by `network_collector.py` as `NETWORK_THREAT` events. |

### Zeek (emulated)
| | |
|---|---|
| **License** | BSD-3-Clause |
| **Website** | https://zeek.org |
| **Version used** | Custom Python emulator (`security_monitor/zeek/zeek_emulator.py`) |
| **How it runs** | Launched as a subprocess by `security_monitor/main.py`; writes to `/var/log/zeek/notice.log` |
| **Used in** | `security_monitor/network_collector.py` tails the notice log; `security_monitor/zeek/hpc_monitor.zeek` defines detection logic |
| **Purpose** | Behavioural network analysis. The Zeek script (`hpc_monitor.zeek`) implements HPC-specific detectors: unauthorized communication pairs, lateral movement via SSH hop chains, fan-out excess (one node connecting to too many peers), protocol mismatches against a per-node service allowlist, and baseline deviation detection. Emits notices: `Unauthorized_Comm`, `Lateral_Movement`, `Fanout_Excess`, `Baseline_Deviation`, `Protocol_Mismatch`. |

### GitLeaks
| | |
|---|---|
| **License** | MIT |
| **Website** | https://github.com/gitleaks/gitleaks |
| **Version used** | v8.30.1 |
| **Used in** | `.github/workflows/build-time-security.yml` (`secret-detection` job) |
| **Config** | `.gitleaks.toml` |
| **Purpose** | Scans full git history for accidentally committed secrets, API keys, and tokens on every push. Blocking job in CI. |

### Bandit
| | |
|---|---|
| **License** | Apache-2.0 |
| **Website** | https://bandit.readthedocs.io |
| **Version used** | ≥ 1.7.5 |
| **Used in** | `.github/workflows/build-time-security.yml` (`sast-bandit` job) |
| **Purpose** | Python SAST (Static Application Security Testing). Scans all Python source for common vulnerabilities (hardcoded passwords, unsafe deserialization, shell injection, etc.). Blocks CI on HIGH severity findings. Uploads SARIF to GitHub Security tab. |

### Semgrep
| | |
|---|---|
| **License** | LGPL-2.1 (OSS engine) |
| **Website** | https://semgrep.dev |
| **Version used** | Latest via pip |
| **Used in** | `.github/workflows/build-time-security.yml` (`sast-semgrep` job) |
| **Rule sets** | `p/python`, `p/secrets`, `p/owasp-top-ten` |
| **Purpose** | Second SAST pass and secrets detection. Covers OWASP Top 10 patterns not caught by Bandit. Blocks CI on ERROR-level findings. Uploads two SARIF reports to GitHub Security tab. |

### Trivy
| | |
|---|---|
| **License** | Apache-2.0 |
| **Website** | https://trivy.dev |
| **Version used** | Latest via install script |
| **Used in** | `.github/workflows/build-time-security.yml` (`trivy` job) |
| **Purpose** | Filesystem CVE scan on the full repository. Blocks CI on CRITICAL unfixed CVEs. HIGH CVEs are advisory only, reported to GitHub Security tab via SARIF. |

### pip-audit
| | |
|---|---|
| **License** | Apache-2.0 |
| **Website** | https://pypi.org/project/pip-audit |
| **Version used** | Latest via pip |
| **Used in** | `.github/workflows/build-time-security.yml` (`sca-pip-audit` job) |
| **Purpose** | Software Composition Analysis (SCA). Scans `dashboard/requirements.txt` and `node_agent/requirements.txt` against the OSV/PyPA advisory database. Blocks CI if any CVE is found. |

### Checkov
| | |
|---|---|
| **License** | Apache-2.0 |
| **Website** | https://checkov.io |
| **Version used** | Latest via pip |
| **Used in** | `.github/workflows/build-time-security.yml` (`checkov` job) |
| **Config** | `.checkov.yaml` |
| **Purpose** | IaC security scanner. Checks `docker-compose.yml` for security misconfigurations (exposed sockets, privileged containers, missing resource limits, etc.). Advisory only — uploads SARIF to GitHub Security tab. |

### Hadolint
| | |
|---|---|
| **License** | GPL-3.0 |
| **Website** | https://github.com/hadolint/hadolint |
| **Version used** | Latest release binary |
| **Used in** | `.github/workflows/build-time-security.yml` (`hadolint` job) |
| **Purpose** | Dockerfile linter. Checks all Dockerfiles for best-practice violations (floating tags, `apt` without `--no-install-recommends`, running as root, etc.). Advisory only. |

### ShellCheck
| | |
|---|---|
| **License** | GPL-3.0 |
| **Website** | https://shellcheck.net |
| **Version used** | From Ubuntu apt |
| **Used in** | `.github/workflows/build-time-security.yml` (`shellcheck` job) |
| **Purpose** | Static analysis for all `.sh` shell scripts (`scripts/`, `controller/entrypoint.sh`, `risk_engine/entrypoint.sh`). Advisory only. |

### Syft (SBOM)
| | |
|---|---|
| **License** | Apache-2.0 |
| **Website** | https://github.com/anchore/syft |
| **Version used** | `anchore/sbom-action@v0` |
| **Used in** | `.github/workflows/sbom.yml` |
| **Purpose** | Generates a Software Bill of Materials (SPDX JSON format) on every merge to `main`. Uploaded as a 90-day retention artifact. |

---

## 2. Container & Infrastructure Tools

| Tool | License | Version | Purpose |
|---|---|---|---|
| **Docker Engine** | Apache-2.0 | — | Container runtime for all 9 services |
| **Docker Compose** | Apache-2.0 | v2 plugin | Multi-container orchestration; defines 4 network segments and the `shared_data` volume |
| **tecnativa/docker-socket-proxy** | MIT | 0.1.2 | Sits between infrastructure services and `/var/run/docker.sock`. Allowlists specific Docker API endpoints per consumer; prevents any service from having unrestricted socket access |
| **ZeroMQ (libzmq)** | MPL-2.0 | — | Underlying C library used by `pyzmq`; provides the PUSH/PULL and REQ/REP message transport between all services |
| **Linux inotify** (kernel subsystem) | GPL-2.0 | — | Kernel interface used by `inotify-simple` in the node agent for real-time filesystem event notifications |
| **iptables** | GPL-2.0 | From Debian apt | Used inside the `risk-engine` container (requires `CAP_NET_ADMIN`) to insert `FORWARD DROP` rules for quarantined node IPs |
| **gosu** | MIT | From Debian apt | Privilege-drop helper used in the `risk-engine` entrypoint to switch from root (needed for iptables setup) to `appuser` |
| **iproute2** | GPL-2.0 | From Ubuntu apt | Installed in `security-monitor` for network interface introspection |
| **Node.js** | MIT | 22 (Alpine image) | Runtime for the Next.js frontend (`aos-frontend` container) |
| **pnpm** | MIT | Via corepack | Package manager for the Next.js frontend; uses frozen lockfile installs |

---

## 3. Python Libraries — by Service

All Python services use Python 3.11 (slim or Ubuntu base image). Pinned versions are from `requirements.txt` files.

### Controller (`controller/`)

| Library | Version | License | Used in | Purpose |
|---|---|---|---|---|
| **PyZMQ** | — | BSD-3-Clause + LGPL | `controller.py` | ZMQ PULL (from agents/monitors) and PUSH (to risk engine) sockets |
| **PyYAML** | — | MIT | `controller.py` | Parses `master_config.yaml` for allowlist, flood threshold, and replay config |

### Risk Engine (`risk_engine/`)

| Library | Version | License | Used in | Purpose |
|---|---|---|---|---|
| **PyZMQ** | 27.1.0 | BSD-3-Clause + LGPL | `engine.py`, `cmd_server.py`, `simulator.py` | ZMQ PULL (telemetry), REP (command server on :5557), PUSH (simulator inject) |
| **docker** (SDK) | 7.1.0 | Apache-2.0 | `router.py`, `network_isolator.py`, `remediation_engine.py`, `cmd_server.py`, `simulator.py` | Pause, stop, network-disconnect containers; exec remediation scripts; introspect container state |
| **PyYAML** | 6.0.3 | MIT | `rules.py`, `scoring.py`, `threat_detector.py`, `remediation_engine.py` | Parses all YAML config files |
| **watchdog** | 6.0.0 | Apache-2.0 | `rules.py` | Watches `rules.yaml` for changes; hot-reloads rules without restarting the engine |

### Host Observer (`host_observer/`)

| Library | Version | License | Used in | Purpose |
|---|---|---|---|---|
| **docker** (SDK) | 7.1.0 | Apache-2.0 | `cluster_observer.py` | Reads container stats, image digests, runtime config via Docker API (no exec into containers) |
| **PyZMQ** | 27.1.0 | BSD-3-Clause + LGPL | `cluster_observer.py` | ZMQ PUSH to send signed telemetry and alert events to the controller |
| **PyYAML** | 6.0.3 | MIT | `cluster_observer.py` | Parses `master_config.yaml`, `approved_images.yaml`, `runtime_baseline.yaml`, `config_hashes.yaml` |

### Security Monitor (`security_monitor/`)

| Library | Version | License | Used in | Purpose |
|---|---|---|---|---|
| **docker** (SDK) | 7.1.0 | Apache-2.0 | `docker_collector.py`, `threat_correlator.py`, `policy_engine.py` | Subscribes to Docker event stream; resolves container IPs for correlation; applies fast-path enforcement (stop/pause/disconnect) |
| **PyZMQ** | 27.1.0 | BSD-3-Clause + LGPL | `event_forwarder.py` | ZMQ PUSH to forward signed security events to the controller |
| **PyYAML** | 6.0.3 | MIT | `policy_engine.py` | Parses `fast_path_policy.yaml` |
| **psutil** | 6.1.1 | BSD-3-Clause | (available in image) | System and process utilities |

### Dashboard (`dashboard/`)

| Library | Version | License | Used in | Purpose |
|---|---|---|---|---|
| **Flask** | 3.1.3 | BSD-3-Clause | `app.py` | Web framework; serves the REST API and legacy HTML dashboard |
| **docker** (SDK) | 7.1.0 | Apache-2.0 | `app.py` | Docker SDK (dependency; used transitively) |
| **PyZMQ** | 25.1.2 | BSD-3-Clause + LGPL | `app.py` | ZMQ REQ socket to send human-review commands (`approve`, `deny`, `restart`, `reset`, `simulate`) to the risk engine's command server on :5557 |

### Node Agent (`node_agent/`)

The node agent represents a **simulated tenant workload** — it has no security dependencies. It runs with a minimal footprint deliberately.

| Library | Version | License | Used in | Purpose |
|---|---|---|---|---|
| — | — | — | — | No third-party dependencies (workload simulator uses stdlib only) |

### Alert Ingestor (`alert_ingestor/`)

No third-party dependencies. Uses Python standard library only (`socket`, `json`, `sqlite3`, `datetime`).

---

## 4. Frontend Libraries

All packages in `dashboard/aos-dashboard/` (Next.js, Node.js 22, TypeScript 5).

### Core Framework

| Package | Version | License | Purpose |
|---|---|---|---|
| **Next.js** | 16.2.9 | MIT | React framework with SSR/SSG; serves the SOC dashboard on port 3000 |
| **React** | 19.2.4 | MIT | UI component model |
| **React DOM** | 19.2.4 | MIT | React DOM renderer |
| **TypeScript** | ^5 | Apache-2.0 | Type-safe development language |

### UI Components & Styling

| Package | Version | License | Purpose |
|---|---|---|---|
| **shadcn** | ^4.11.0 | MIT | Component library built on Radix UI primitives |
| **Radix UI** | ^1.6.0 | MIT | Accessible, unstyled headless UI primitives (dialogs, dropdowns, tabs, etc.) |
| **Tailwind CSS** | ^4 | MIT | Utility-first CSS framework |
| **tailwind-merge** | ^3.6.0 | MIT | Merges Tailwind class names without conflicts |
| **class-variance-authority** | ^0.7.1 | MIT | Type-safe component variant API |
| **clsx** | ^2.1.1 | MIT | Conditional className construction |
| **tw-animate-css** | ^1.4.0 | MIT | CSS animation utilities for Tailwind |
| **lucide-react** | ^1.21.0 | ISC | SVG icon library |

### Data Fetching & State

| Package | Version | License | Purpose |
|---|---|---|---|
| **@tanstack/react-query** | ^5.101.0 | MIT | Server state management; auto-refresh polling for live dashboard panels |
| **axios** | ^1.18.0 | MIT | HTTP client for API calls to Flask backend |
| **use-debounce** | ^10.1.1 | MIT | Debounced hook for search/filter inputs |

### Data Display

| Package | Version | License | Purpose |
|---|---|---|---|
| **recharts** | ^3.8.1 | MIT | Composable React charting library; used for risk score sparklines, severity bars, and threat distribution charts |
| **@tanstack/react-table** | ^8.21.3 | MIT | Headless table with sorting, filtering, and pagination for alert feeds and node tables |
| **react-countup** | ^6.5.3 | MIT | Animated number counters for the stat tiles |
| **date-fns** | ^4.4.0 | MIT | Date formatting and relative time display |
| **sonner** | ^2.0.7 | MIT | Toast notification system for command feedback (approve/deny/simulate results) |

### Dev Tools

| Package | Version | License | Purpose |
|---|---|---|---|
| **ESLint** | ^9 | MIT | JavaScript/TypeScript linter |
| **eslint-config-next** | 16.2.9 | MIT | Next.js ESLint rules |
| **@tailwindcss/postcss** | ^4 | MIT | PostCSS plugin for Tailwind CSS processing |

---

## 5. CI/CD & Build-Time Security Tools

All run in GitHub Actions on every push and pull request (see `.github/workflows/build-time-security.yml`).

| Tool | Version | License | Stage | Blocking? | Purpose |
|---|---|---|---|---|---|
| **GitLeaks** | 8.30.1 | MIT | 1 — serial | ✅ Yes | Secret and credential detection across full git history |
| **yamllint** | Latest (pip) | MIT | 1 — serial | ✅ Yes | YAML syntax and style validation for all config files |
| **Bandit** | ≥ 1.7.5 | Apache-2.0 | 2 — parallel | ✅ Yes | Python SAST; blocks on HIGH severity |
| **Semgrep** | Latest (pip) | LGPL-2.1 | 2 — parallel | ✅ Yes | SAST + secrets; p/python + p/secrets + p/owasp-top-ten |
| **pip-audit** | Latest (pip) | Apache-2.0 | 2 — parallel | ✅ Yes | Python dependency CVE scan (OSV database) |
| **ShellCheck** | From apt | GPL-3.0 | 2 — parallel | ❌ Advisory | Shell script static analysis |
| **Hadolint** | Latest release | GPL-3.0 | 3 — parallel | ❌ Advisory | Dockerfile best-practice linting |
| **Checkov** | Latest (pip) | Apache-2.0 | 3 — parallel | ❌ Advisory | IaC scan on `docker-compose.yml` |
| **Trivy** | Latest | Apache-2.0 | 3 — parallel | ✅ Yes (CRITICAL) | Filesystem CVE scan; blocks on CRITICAL unfixed |
| **Syft** | `sbom-action@v0` | Apache-2.0 | On merge to main | — | SPDX SBOM generation |

---

## 6. Python Standard Library Modules

No installation required — part of Python 3.11.

| Module | Used in | Purpose |
|---|---|---|
| `sqlite3` | `store.py`, `app.py`, `alert_ingestor.py` | Embedded database engine for all event, alert, forensic, and identity storage |
| `hmac` | `secure_messenger.py` (shared, controller, node agent) | HMAC-SHA256 message signing and constant-time verification |
| `hashlib` | `secure_messenger.py`, `cluster_observer.py`, `check_config_integrity.py`, `generate_baseline.py` | SHA-256 digests for HMAC, file integrity, and baseline generation |
| `json` | multiple | Event serialisation, evidence payloads, SARIF parsing |
| `uuid` | `secure_messenger.py`, `controller.py`, `alert_manager.py`, `simulator.py` | UUID4 for `msg_id`, `alert_id`, rogue node simulation IDs |
| `threading` | `engine.py`, `security_monitor/main.py`, `rules.py`, `secure_messenger.py` | Heartbeat checker, pipeline stage threads, rule hot-reload |
| `queue` | `security_monitor/main.py`, all pipeline modules | Thread-safe inter-stage event passing in the security monitor pipeline |
| `subprocess` | `security_monitor/main.py`, `cmd_server.py`, `network_isolator.py` | Launching Suricata/Zeek subprocesses; iptables commands |
| `collections.deque` / `defaultdict` | `controller.py`, `correlation.py`, `threat_detector.py`, `event_forwarder.py`, `docker_collector.py` | Sliding-window state for replay guard, flood guard, rate limiter, correlation |
| `socket` | `router.py`, `alert_ingestor.py` | UDP syslog forwarding to the alert ingestor |
| `os` | multiple | File I/O, environment variables, `fsync` for atomic offset writes, `makedirs` |
| `pathlib` | `rules.py`, `generate_baseline.py`, `secure_messenger.py`, `check_config_integrity.py` | Path construction and file operations |
| `time` | multiple | Timestamps, sleep intervals, sliding-window eviction |
| `datetime` | multiple | UTC timestamp generation, ISO-8601 formatting, relative time display |
| `secrets` | `secure_messenger.py` | Cryptographically secure ephemeral HMAC secret fallback |
| `logging` | all Python files | Structured logging with per-service loggers |
| `signal` | `security_monitor/main.py` | Graceful shutdown of Suricata and Zeek subprocesses on SIGTERM/SIGINT |
| `argparse` | `generate_baseline.py`, `check_config_integrity.py` | CLI argument parsing |
| `ipaddress` | `network_isolator.py` | IP address validation before passing to iptables subprocess (injection prevention) |

---

## 7. Quick-Reference Summary

### By Service

| Service | Third-party Python packages | External tools / runtimes |
|---|---|---|
| `controller` | pyzmq, pyyaml | ZeroMQ |
| `risk-engine` | pyzmq, docker, pyyaml, watchdog | ZeroMQ, iptables, gosu |
| `host-observer` | docker, pyzmq, pyyaml | ZeroMQ, docker-socket-proxy |
| `security-monitor` | docker, pyzmq, pyyaml, psutil | **Suricata**, **Zeek** (emulator), ZeroMQ |
| `dashboard` (Flask) | flask, docker, pyzmq | ZeroMQ |
| `aos-frontend` | Next.js, React, Recharts, TanStack Query/Table, shadcn/Radix, Tailwind, axios, … | Node.js 22, pnpm |
| `alert_ingestor` | _(stdlib only)_ | — |
| `node1–4` | _(stdlib only — simulated workload)_ | — |

### External Security Engines

| Tool | Role | Runs as |
|---|---|---|
| **Falco** | Kernel syscall monitoring (eBPF) | Host-native process |
| **Suricata** | Network IDS / deep-packet inspection | Subprocess inside `security-monitor` |
| **Zeek** | Behavioural network analysis | Python emulator subprocess inside `security-monitor` |
| **docker-socket-proxy** | Docker API gateway / allowlister | Dedicated container |

### CI/CD Tools

GitLeaks · yamllint · Bandit · Semgrep · pip-audit · ShellCheck · Hadolint · Checkov · Trivy · Syft
