import time
import logging
import docker

log = logging.getLogger("docker_collector")

def run_docker_collector(event_queue):
    log.info("Docker collector thread started.")
    while True:
        try:
            client = docker.from_env()
            for event in client.events(decode=True):
                if event.get("Type") == "container":
                    action = event.get("Action", "")
                    actor = event.get("Actor", {})
                    name = actor.get("Attributes", {}).get("name", "")
                    
                    # We are only interested in events for node1-4
                    if name in ["node1", "node2", "node3", "node4"]:
                        evt = {
                            "source": "docker",
                            "node": name,
                            "action": action,
                            "timestamp": event.get("time"),
                            "status": event.get("status"),
                            "id": event.get("id"),
                            "image": actor.get("Attributes", {}).get("image", ""),
                            "exit_code": actor.get("Attributes", {}).get("exitCode", "")
                        }
                        log.info(f"Container event: node={name} action={action}")
                        event_queue.put(evt)
        except Exception as e:
            log.error(f"Error in Docker event listener: {e}")
            time.sleep(5)
