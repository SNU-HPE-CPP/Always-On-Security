import logging
import socket
import json

log = logging.getLogger(__name__)

WAZUH_MANAGER_IP = "wazuh"
WAZUH_PORT = 514


class Router:
    def __init__(self):
        self._docker = None

    @classmethod
    def from_yaml(cls, thresholds_path: str) -> "Router":
        return cls()

    def _get_docker(self):
        if self._docker is None:
            try:
                import docker

                self._docker = docker.from_env()
            except Exception as e:
                log.error(f"Docker client init failed: {e}")

        return self._docker

    def dispatch(self, decision) -> None:

        node = decision.node

        bucket = decision.bucket

        score = decision.cumulative_score

        corr_tag = " [CORRELATED]" if decision.correlated else ""

        rule_ids = [r[0] for r in decision.matched_rules]

        reasons = decision.raw_event.get(
            "reasons",
            [],
        )

        log.info(
            f"[{bucket.upper()}]{corr_tag} "
            f"node={node} "
            f"cumulative={score:.2f} "
            f"event={decision.event_score:.4f} "
            f"rules={rule_ids}"
        )

        if bucket == "silent":
            return

        elif bucket == "auto":

            log.warning(f"[AUTO-REMEDIATION] " f"node={node} " f"score={score:.2f}")

            self._send_wazuh_alert(
                node=node,
                risk_score=score,
                reasons=reasons,
                rule_ids=rule_ids,
                correlated=decision.correlated,
                severity="WARNING",
            )

        elif bucket == "human":

            log.warning(f"[HUMAN_REVIEW] " f"node={node} " f"score={score:.2f}")

            self._pause(node)

            self._send_wazuh_alert(
                node=node,
                risk_score=score,
                reasons=reasons,
                rule_ids=rule_ids,
                correlated=decision.correlated,
                severity="HIGH",
            )

        elif bucket == "quarantine":

            log.critical(f"[QUARANTINE] " f"node={node} " f"score={score:.2f}")

            self._quarantine(node)

            self._send_wazuh_alert(
                node=node,
                risk_score=score,
                reasons=reasons,
                rule_ids=rule_ids,
                correlated=decision.correlated,
                severity="CRITICAL",
            )

    def _pause(self, node: str) -> None:
        client = self._get_docker()
        if client is None:
            log.error(f"Cannot pause {node}: Docker unavailable")
            return
        try:
            container = client.containers.get(node)
            container.pause()
            log.warning(f"Node {node} paused for human review")
        except Exception as e:
            log.error(f"Pause failed for {node}: {e}")

    def _quarantine(self, node: str) -> None:

        client = self._get_docker()

        if client is None:
            log.error(f"Cannot quarantine {node}: " f"Docker unavailable")
            return

        try:

            container = client.containers.get(node)

            container.stop()

            log.critical(f"Node {node} quarantined " f"(container stopped)")

        except Exception as e:

            log.error(f"Quarantine failed for " f"{node}: {e}")

    def _send_wazuh_alert(
        self,
        node: str,
        risk_score: float,
        reasons: list,
        rule_ids: list,
        correlated: bool,
        severity: str = "CRITICAL",
    ) -> None:

        payload = {
            "source": "always-on-security",
            "severity": severity,
            "node": node,
            "risk_score": risk_score,
            "matched_rules": rule_ids,
            "correlated": correlated,
            "reasons": reasons,
        }

        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM,
            )

            sock.sendto(
                json.dumps(payload).encode(),
                (
                    WAZUH_MANAGER_IP,
                    WAZUH_PORT,
                ),
            )

            sock.close()

            log.info(
                f"[WAZUH] Alert sent " f"for {node} " f"(Risk Score: {risk_score})"
            )

        except Exception as e:

            log.error(f"[WAZUH] Failed to send alert: {e}")
