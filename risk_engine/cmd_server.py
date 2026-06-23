import zmq
import logging
import threading
import subprocess
import os
import simulator

log = logging.getLogger("cmd_server")

def run_cmd_server(store, router, engine_state):
    """
    Background thread to process ZMQ REQ commands from the dashboard.
    engine_state is a dict containing {"last_offset": <int>}
    """
    try:
        log.info("Entering run_cmd_server")

        ctx = zmq.Context.instance()

        sock = ctx.socket(zmq.REP)

        sock.bind("tcp://*:5557")

        log.info("ZMQ command server listening on tcp://*:5557")

    except Exception as e:
        log.exception("Failed starting command server")
        raise

    while True:
        try:
            req = sock.recv_json()
            action = req.get("action")
            node = req.get("node")
            log.info(f"Received command: {action} for node: {node}")

            if action == "approve":
                # Precondition check
                status = store.get_node_status(node)
                if status != "awaiting_approval":
                    sock.send_json({"ok": False, "error": f"Node in state {status}, not awaiting_approval"})
                    continue

                def _do_approve():
                    try:
                        # 1. Unpause via Docker SDK
                        client = router._get_docker()
                        if client:
                            container = client.containers.get(node)
                            container.reload()
                            if container.status == "paused":
                                container.unpause()
                                log.info(f"Node {node} unpaused")
                        
                        # 2. Remove iptables DROP rule
                        isolated_ip = store.get_isolated_ip(node)
                        if isolated_ip:
                            subprocess.run(["iptables", "-D", "FORWARD", "-s", isolated_ip, "-j", "DROP"], capture_output=True)
                            log.info(f"Removed iptables DROP rule for {node} ({isolated_ip})")
                        
                        # 3. Reset scores & status
                        store.reset_node_score(node)
                        store.set_isolated_ip(node, None)
                        store.update_node_status(node, "idle", 0.0)
                        log.info(f"Node {node} approved and reset to idle")
                    except Exception as e:
                        log.error(f"Error during approve for {node}: {e}")

                _do_approve()
                sock.send_json({"ok": True, "status": "idle"})

            elif action == "restart":
                status = store.get_node_status(node)
                if status not in ("quarantined", "unresponsive"):
                    sock.send_json({"ok": False, "error": f"Node in state {status}, cannot restart"})
                    continue

                def _do_restart():
                    try:
                        # 1. Remove iptables DROP rule
                        isolated_ip = store.get_isolated_ip(node)
                        if isolated_ip:
                            subprocess.run(["iptables", "-D", "FORWARD", "-s", isolated_ip, "-j", "DROP"], capture_output=True)
                            log.info(f"Removed iptables DROP rule for {node} ({isolated_ip})")

                        # 2. Start/unpause container
                        client = router._get_docker()
                        if client:
                            container = client.containers.get(node)
                            container.reload()
                            if container.status == "paused":
                                container.unpause()
                            elif container.status in ("exited", "dead", "removing"):
                                container.start()
                            log.info(f"Node {node} restarted")

                        # 3. Reset scores & status
                        store.reset_node_score(node)
                        store.set_isolated_ip(node, None)
                        store.update_node_status(node, "idle", 0.0)
                        log.info(f"Node {node} restarted and reset to idle")
                    except Exception as e:
                        log.error(f"Error during restart for {node}: {e}")

                _do_restart()
                sock.send_json({"ok": True, "status": "idle"})

            elif action == "reset":
                def _do_reset():
                    try:
                        # 1. DB reset
                        store.reset_all_tables()
                        # 2. Memory reset
                        engine_state["last_offset"] = 0
                        
                        # 3. Controller reset file
                        if os.path.exists("/data/controller.offset"):
                            os.remove("/data/controller.offset")
                            
                        # 4. Container restart
                        client = router._get_docker()
                        if client:
                            for n in ["node1", "node2", "node3", "node4"]:
                                try:
                                    container = client.containers.get(n)
                                    container.reload()
                                    if container.status in ("exited", "dead", "removing", "paused"):
                                        if container.status == "paused":
                                            container.unpause()
                                        else:
                                            container.start()
                                except Exception as inner_e:
                                    log.warning(f"Could not restart {n}: {inner_e}")
                        
                        # 5. Remove any leftover DROP rules by scanning node_status
                        for n in ["node1", "node2", "node3", "node4"]:
                            ip = store.get_isolated_ip(n)
                            if ip:
                                subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], capture_output=True)
                                store.set_isolated_ip(n, None)

                        log.info("System reset complete")
                    except Exception as e:
                        log.error(f"Error during reset: {e}")
                
                _do_reset()
                sock.send_json({"ok": True})

            elif action == "simulate":
                attack = req.get("attack", "")
                node   = req.get("node")   # may be None for global attacks
                result = simulator.dispatch(attack=attack, node=node, store=store)
                sock.send_json(result)

            else:
                sock.send_json({"ok": False, "error": "Unknown action"})

        except Exception as e:
            log.error(f"Cmd server error: {e}")
            try:
                sock.send_json({"ok": False, "error": str(e)})
            except:
                pass