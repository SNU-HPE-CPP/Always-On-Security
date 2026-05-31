"""
Always-On Security — Job Provider
Simulates an HPC job submission queue.
Generates random jobs and pushes them to the controller.
"""

import zmq
import uuid
import random
import time
from datetime import datetime

context = zmq.Context()

sender = context.socket(zmq.PUSH)
sender.connect("tcp://controller:5555")

print("[PROVIDER] Started — generating HPC jobs")

while True:

    job = {
        "job_id": str(uuid.uuid4()),
        "job_type": random.choice([
            "cpu",
            "file_write",
            "memory_access",
        ]),
        "duration": random.randint(5, 15),
        "submitted_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    sender.send_json(job)

    print(f"[PROVIDER] Generated {job['job_id'][:8]}... type={job['job_type']}")

    time.sleep(random.randint(3, 8))