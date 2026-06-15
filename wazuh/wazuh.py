import socket
import json
import sqlite3
from datetime import datetime

HOST = "0.0.0.0"
PORT = 5514  # nosemgrep — port < 1024 requires root; 5514 is equivalent for intra-cluster syslog

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

DB_PATH = "/data/events.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS wazuh_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT,
            severity TEXT,
            node TEXT,
            risk_score REAL,
            reasons TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

print(f"[WAZUH] Mock Wazuh Manager listening on UDP {PORT} and saving to SQLite")

while True:

    data, addr = sock.recvfrom(4096)

    try:

        alert = json.loads(data.decode())

        print("\n" + "=" * 70)
        print("WAZUH SECURITY ALERT")
        print("=" * 70)

        print(f"Time       : {datetime.now()}")
        print(f"Source     : {alert.get('source')}")
        print(f"Severity   : {alert.get('severity')}")
        print(f"Node       : {alert.get('node')}")
        print(f"Risk Score : {alert.get('risk_score')}")

        print("\nReasons:")

        for reason in alert.get("reasons", []):
            print(f" - {reason}")

        print("=" * 70)

        # Save to SQLite
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute("""
                INSERT INTO wazuh_alerts (timestamp, source, severity, node, risk_score, reasons)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                alert.get("source"),
                alert.get("severity"),
                alert.get("node"),
                alert.get("risk_score"),
                json.dumps(alert.get("reasons", []))
            ))
            conn.commit()
            conn.close()
        except Exception as db_e:
            print(f"Failed to save alert to DB: {db_e}")

    except Exception as e:

        print(f"Failed to parse alert: {e}")
