# Always-On Security System

A distributed security monitoring and automated remediation system built using Docker, Python, ZeroMQ, SQLite, and Flask.

## Overview

This project simulates an Always-On Security Architecture for a distributed computing environment.

The system continuously monitors multiple nodes, detects suspicious activity, calculates risk scores, stores events, and automatically responds to potentially compromised nodes.

### Current Features

* Distributed node simulation using Docker containers
* Telemetry collection (CPU, memory, process count)
* Local anomaly detection on each node
* Event-driven communication using ZeroMQ
* Centralized controller
* SQLite-based event storage
* Cumulative node risk scoring
* Automated node quarantine/remediation
* Flask dashboard for monitoring and observability

---

## Architecture

```text
Node 1 ─┐
Node 2 ─┼────► Controller ───► SQLite Database
Node 3 ─┤            │
Node 4 ─┘            │
                     ▼
             Risk Analysis Engine
                     │
                     ▼
           Automated Remediation
                     │
                     ▼
               Flask Dashboard
```

---

## Suspicious Activity Detection

Currently, a node is marked as suspicious if it exhibits one or more of the following:

* High CPU usage
* High memory usage
* Excessive number of running processes
* Suspicious process names (e.g., `stress`, `nmap`, `hydra`, `netcat`)

These detections are currently rule-based and serve as a proof-of-concept implementation.

---

## Project Structure

```text
Always-On-Security/
│
├── controller/
│   ├── controller.py
│   ├── Dockerfile
│   └── requirements.txt
│
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
├── data/
│
├── docker-compose.yml
└── .gitignore
```

---

## Prerequisites

Install the following:

### Ubuntu / Linux

```bash
sudo apt update
sudo apt install git docker.io docker-compose-plugin -y
```

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

Build and start all services:

```bash
docker compose up --build
```

The following containers should start:

* controller
* dashboard
* node1
* node2
* node3
* node4

---

## Access Dashboard

Open:

```text
http://localhost:5000
```

You should see:

* Event statistics
* Risk information
* Recent security events
* System activity

---

## Verify Running Containers

```bash
docker ps
```

Expected containers:

```text
controller
dashboard
node1
node2
node3
node4
```

---

## Generate a Test Alert

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

Stop the process:

```bash
CTRL + C
```

---

## Useful Commands

### View Logs

```bash
docker compose logs -f
```

### Open Controller Container

```bash
docker exec -it controller bash
```

### Open Dashboard Container

```bash
docker exec -it dashboard bash
```

### Open Node Container

```bash
docker exec -it node1 bash
```

### Stop System

```bash
docker compose down
```


* Distributed monitoring
* Event collection
* Risk analysis
* Automated remediation
* Dashboard visualization
