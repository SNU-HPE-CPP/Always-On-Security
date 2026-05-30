import time
import socket
import psutil
import zmq

# node identity
node_name = socket.gethostname()

# create ZeroMQ context
context = zmq.Context()

# create PUSH socket
sender = context.socket(zmq.PUSH)

# connect to controller
sender.connect("tcp://controller:5555")

# suspicious process names
SUSPICIOUS_PROCESSES = [
    "nmap",
    "hydra",
    "nc",
    "netcat",
    "stress"
]

while True:

    # collect telemetry
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    process_count = len(psutil.pids())
    print(cpu, memory, process_count)
    # default event
    event_type = "NORMAL"

    # explanation list
    reasons = []

    # ---------- RULE 1 ----------
    # High CPU usage

    if cpu > 10:
        event_type = "SUSPICIOUS_ACTIVITY"
        reasons.append("High CPU usage detected")

    # ---------- RULE 2 ----------
    # High memory usage

    if memory > 50:
        event_type = "SUSPICIOUS_ACTIVITY"
        reasons.append("High memory usage detected")

    # ---------- RULE 3 ----------
    # Too many running processes

    if process_count > 300:
        event_type = "SUSPICIOUS_ACTIVITY"
        reasons.append("Too many running processes")

    # ---------- RULE 4 ----------
    # Suspicious process names

    for proc in psutil.process_iter(['name']):

        try:
            process_name = proc.info['name']

            if process_name in SUSPICIOUS_PROCESSES:

                event_type = "SUSPICIOUS_ACTIVITY"

                reasons.append(
                    f"Suspicious process detected: {process_name}"
                )

        except:
            pass

    # create event object

    event = {
        "node": node_name,
        "cpu_usage": cpu,
        "memory_usage": memory,
        "process_count": process_count,
        "event_type": event_type,
        "reasons": reasons
    }

    print(f"[{node_name}] Sending event...")

    # send event to controller
    sender.send_json(event)

    # wait before next cycle
    time.sleep(5)
