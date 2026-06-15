import ipaddress
import logging
import subprocess
import docker

log = logging.getLogger("network_isolator")

class NetworkIsolator:
    def __init__(self):
        self.docker_client = None

    def _get_docker(self):
        if not self.docker_client:
            try:
                self.docker_client = docker.from_env()
            except Exception as e:
                log.error(f"Failed to initialize Docker SDK: {e}")
        return self.docker_client

    def pause_node(self, node: str) -> bool:
        client = self._get_docker()
        if not client:
            return False
        try:
            container = client.containers.get(node)
            container.reload()
            if container.status == "paused":
                log.info(f"Node {node} is already paused.")
                return True
            container.pause()
            log.warning(f"Node {node} paused via Docker SDK.")
            return True
        except Exception as e:
            log.error(f"Failed to pause {node}: {e}")
            return False

    def unpause_node(self, node: str) -> bool:
        client = self._get_docker()
        if not client:
            return False
        try:
            container = client.containers.get(node)
            container.reload()
            if container.status != "paused":
                log.info(f"Node {node} is not paused.")
                return True
            container.unpause()
            log.warning(f"Node {node} unpaused via Docker SDK.")
            return True
        except Exception as e:
            log.error(f"Failed to unpause {node}: {e}")
            return False

    def stop_node(self, node: str) -> bool:
        client = self._get_docker()
        if not client:
            return False
        try:
            container = client.containers.get(node)
            container.reload()
            if container.status in ["exited", "dead"]:
                log.info(f"Node {node} is already stopped.")
                return True
            container.stop()
            log.critical(f"Node {node} stopped via Docker SDK.")
            return True
        except Exception as e:
            log.error(f"Failed to stop {node}: {e}")
            return False

    def isolate_node(self, node: str) -> bool:
        """Disconnects the container from data networks (compute-net and storage-net)."""
        client = self._get_docker()
        if not client:
            return False
        try:
            container = client.containers.get(node)
            success = True
            for net_name in ["compute-net", "storage-net"]:
                try:
                    net = client.networks.get(net_name)
                    net.disconnect(container)
                    log.warning(f"Disconnected {node} from network {net_name} via Docker SDK.")
                except Exception as net_err:
                    log.debug(f"Docker network disconnect from {net_name} failed (may not be connected): {net_err}")
            return success
        except Exception as e:
            log.error(f"Failed to isolate {node} networks: {e}")
            return False

    def quarantine_network(self, node: str) -> bool:
        """Applies iptables DROP rules for the node's IPs in the FORWARD chain.

        The risk-engine container requires CAP_NET_ADMIN (set in docker-compose.yml)
        and must have iptables installed (see Dockerfile). No external containers are
        spawned — the privileged-helper-container fallback was removed as a
        supply-chain risk (it pulled python:3.11-slim with apt-get at runtime).
        """
        client = self._get_docker()
        if not client:
            return False
        try:
            container = client.containers.get(node)
            container.reload()
            networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})

            ips = []
            for net_detail in networks.values():
                ip = net_detail.get("IPAddress")
                if ip:
                    ips.append(ip)

            if not ips:
                log.error(f"Cannot quarantine network for {node}: no container IPs found")
                return False

            success = True
            for ip in ips:
                try:
                    # Validate the IP is a simple dotted-decimal address before
                    # passing it to subprocess to prevent command injection.
                    ipaddress.ip_address(ip)  # raises ValueError on malformed input

                    drop_rule = ["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"]
                    result = subprocess.run(
                        drop_rule,
                        check=True,
                        capture_output=True,
                        timeout=10,
                    )
                    log.warning(f"Applied iptables FORWARD DROP for {node} IP {ip}")
                except ValueError:
                    log.error(f"Skipping malformed IP address '{ip}' for node {node}")
                    success = False
                except subprocess.CalledProcessError as cpe:
                    log.error(
                        f"iptables DROP failed for {ip} (node={node}): "
                        f"returncode={cpe.returncode} stderr={cpe.stderr.decode().strip()}"
                    )
                    success = False
                except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
                    log.error(
                        f"iptables not available or timed out for {ip} (node={node}): {exc}. "
                        "Ensure iptables is installed in the risk-engine image and "
                        "CAP_NET_ADMIN is granted in docker-compose.yml."
                    )
                    success = False
            return success
        except Exception as e:
            log.error(f"quarantine_network failed for {node}: {e}")
            return False
