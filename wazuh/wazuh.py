import socket
import json
from datetime import datetime

HOST = "0.0.0.0"
PORT = 514

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

print(f"[WAZUH] Mock Wazuh Manager listening on UDP {PORT}")

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

    except Exception as e:

        print(f"Failed to parse alert: {e}")
