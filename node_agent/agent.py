import os
import time
import socket

def main():
    node_name = os.getenv("NODE_NAME", socket.gethostname())
    print(f"[{node_name}] Workload service started. Running customer workload...")
    
    # Simulate a steady-state customer workload
    while True:
        # Perform some dummy calculations to keep CPU active at a very low level
        res = 0
        for i in range(100000):
            res += i
        time.sleep(5)

if __name__ == '__main__':
    main()
