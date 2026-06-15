import time
import json
import os
import logging
import threading

log = logging.getLogger("network_collector")

def _make_json_safe(obj):
    """Recursively convert non-serializable types (set, bytes) to JSON-safe equivalents."""
    if isinstance(obj, set):
        return sorted(_make_json_safe(v) for v in obj)
    if isinstance(obj, dict):
        return {k: _make_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_make_json_safe(v) for v in obj]
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    return obj


def tail_file(file_path):
    if not os.path.exists(file_path):
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        open(file_path, "a").close()
        
    with open(file_path, "r") as f:
        # Seek to end on startup to only parse new events
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line

def run_network_collector(event_queue):
    log.info("Network collector thread started.")
    
    def watch_suricata():
        suricata_path = "/var/log/suricata/eve.json"
        log.info(f"Tailing Suricata EVE log: {suricata_path}")
        for line in tail_file(suricata_path):
            try:
                data = json.loads(line)
                if data.get("event_type") == "alert":
                    alert = data.get("alert", {})
                    src_ip = data.get("src_ip", "")
                    dest_ip = data.get("dest_ip", "")
                    # Suricata alert.severity: 1=CRITICAL, 2=HIGH, 3=MEDIUM, 4+=LOW
                    suricata_sev = int(alert.get("severity", 3))
                    if suricata_sev == 1:
                        mapped_sev = "CRITICAL"
                    elif suricata_sev == 2:
                        mapped_sev = "HIGH"
                    elif suricata_sev == 3:
                        mapped_sev = "MEDIUM"
                    else:
                        mapped_sev = "LOW"
                    evt = {
                        "source": "suricata",
                        "timestamp": data.get("timestamp"),
                        "threat_type": "NETWORK_THREAT",
                        "severity": mapped_sev,
                        "description": alert.get("signature", "Suricata Alert"),
                        "src_ip": src_ip,
                        "dest_ip": dest_ip,
                        "proto": data.get("proto", ""),
                        "dest_port": data.get("dest_port", 0)
                    }
                    log.info(f"Suricata alert: {evt['description']} src={src_ip}")
                    event_queue.put(evt)
            except Exception as e:
                log.error(f"Error parsing Suricata log line: {e}")

    def watch_zeek():
        zeek_path = "/var/log/zeek/notice.log"
        log.info(f"Tailing Zeek notice log: {zeek_path}")
        for line in tail_file(zeek_path):
            try:
                data = json.loads(line)
                # Parse notice.log record
                # Notice can be "Unexpected listening ports detected" or enum notices like "Lateral_Movement"
                notice_type = data.get("notice") or data.get("note") or "ZEEK_ALERT"
                if notice_type == "Zeek shim started":
                    continue
                    
                evt = {
                    "source": "zeek",
                    "timestamp": data.get("ts"),
                    "threat_type": notice_type,
                    "severity": data.get("severity") or ("HIGH" if "Lateral" in str(notice_type) else "MEDIUM"),
                    "description": data.get("msg") or data.get("notice") or "",
                    "src_ip": data.get("src") or data.get("host") or "",
                    "dest_ip": data.get("dst") or "",
                    "evidence": _make_json_safe(data)
                }
                log.info(f"Zeek notice: {evt['threat_type']} src={evt['src_ip']}")
                event_queue.put(evt)
            except Exception as e:
                log.error(f"Error parsing Zeek log line: {e}")
                
    t1 = threading.Thread(target=watch_suricata, daemon=True)
    t2 = threading.Thread(target=watch_zeek, daemon=True)
    t1.start()
    t2.start()
