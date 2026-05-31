import socket
import json

WAZUH_MANAGER_IP = "wazuh"
WAZUH_PORT = 514


class WazuhController:

    def __init__(self, manager_ip=WAZUH_MANAGER_IP, port=WAZUH_PORT):
        self.manager_ip = manager_ip
        self.port = port

    def send_alert(self, node, risk_score, reasons):

        payload = {
            "source": "always-on-security",
            "severity": "CRITICAL",
            "node": node,
            "risk_score": risk_score,
            "reasons": reasons,
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            sock.sendto(json.dumps(payload).encode(), (self.manager_ip, self.port))

            sock.close()

            print(f"[WAZUH] Alert sent for {node} " f"(Risk Score: {risk_score})")

        except Exception as e:
            print(f"[WAZUH] Failed to send alert: {e}")
