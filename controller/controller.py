import docker
import zmq
import json
import sqlite3
from datetime import datetime

from wazuh_controller import WazuhController

# -----------------------------
# DATABASE SETUP
# -----------------------------

conn = sqlite3.connect("/data/events.db")

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS events (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    timestamp TEXT,

    node TEXT,

    cpu_usage REAL,

    memory_usage REAL,

    process_count INTEGER,

    event_type TEXT,

    reasons TEXT,

    risk_score INTEGER
)
""")

conn.commit()

# -----------------------------
# RISK ENGINE
# -----------------------------

node_risk_scores = {}

docker_client = docker.from_env()

wazuh = WazuhController()

# -----------------------------
# ZEROMQ SETUP
# -----------------------------

context = zmq.Context()

socket = context.socket(zmq.PULL)

socket.bind("tcp://*:5555")

print("Controller listening on port 5555...\n")

# -----------------------------
# EVENT LOOP
# -----------------------------

while True:

    message = socket.recv_json()

    node = message["node"]

    reasons = message["reasons"]

    # initialize node score

    if node not in node_risk_scores:
        node_risk_scores[node] = 0

    # -----------------------------
    # RISK CALCULATION
    # -----------------------------

    risk_increment = 0

    for reason in reasons:

        if "CPU" in reason:
            risk_increment += 20

        if "memory" in reason:
            risk_increment += 20

        if "Suspicious process" in reason:
            risk_increment += 40

        if "Too many processes" in reason:
            risk_increment += 25

    # update cumulative risk

    node_risk_scores[node] += risk_increment

    current_risk = node_risk_scores[node]

    # -----------------------------
    # WAZUH ALERTING
    # -----------------------------

    if current_risk >= 50:

        wazuh.send_alert(node=node, risk_score=current_risk, reasons=reasons)

    # -----------------------------
    # DISPLAY EVENT
    # -----------------------------

    print("=" * 60)

    print("EVENT RECEIVED")

    print(json.dumps(message, indent=4))

    print(f"\nCURRENT NODE RISK SCORE: {current_risk}")

    # -----------------------------
    # SEVERITY & REMEDIATION
    # -----------------------------

    if current_risk >= 100:

        print("SEVERITY: HIGH RISK")

        print(f"QUARANTINING NODE: {node}")

        try:

            container = docker_client.containers.get(node)

            container.stop()

            print(f"Node {node} has been quarantined.")

        except Exception as e:

            print(f"Remediation failed: {e}")

    elif current_risk >= 50:

        print("SEVERITY: MEDIUM RISK")

    else:

        print("SEVERITY: LOW RISK")

    # -----------------------------
    # STORE EVENT
    # -----------------------------

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        """
    INSERT INTO events (

        timestamp,
        node,
        cpu_usage,
        memory_usage,
        process_count,
        event_type,
        reasons,
        risk_score

    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            timestamp,
            message["node"],
            message["cpu_usage"],
            message["memory_usage"],
            message["process_count"],
            message["event_type"],
            json.dumps(message["reasons"]),
            current_risk,
        ),
    )

    conn.commit()

    print("Event stored in SQLite database.\n")
