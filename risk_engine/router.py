import logging
import yaml

log = logging.getLogger(__name__)


class Router:
    def __init__(self):
        self._docker = None

    @classmethod
    def from_yaml(cls, thresholds_path: str) -> "Router":
        # thresholds loaded for future Mattermost/Ansible config — stub for now
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

        log.info(
            f"[{bucket.upper()}]{corr_tag} node={node} "
            f"cumulative={score:.2f} event={decision.event_score:.4f} rules={rule_ids}"
        )

        if bucket == "silent":
            pass  # log only

        elif bucket == "auto":
            log.warning(
                f"[AUTO-REMEDIATION] node={node} score={score:.2f} "
                f"— Ansible stub (Layer 4 deferred)"
            )

        elif bucket == "human":
            log.warning(
                f"[HUMAN_REVIEW] node={node} score={score:.2f} "
                f"— Mattermost stub (Layer 5 deferred)"
            )

        elif bucket == "quarantine":
            log.critical(
                f"[QUARANTINE] node={node} score={score:.2f} — stopping container"
            )
            self._quarantine(node)

    def _quarantine(self, node: str) -> None:
        client = self._get_docker()
        if client is None:
            log.error(f"Cannot quarantine {node}: Docker unavailable")
            return
        try:
            container = client.containers.get(node)
            container.stop()
            log.critical(f"Node {node} quarantined (container stopped).")
        except Exception as e:
            log.error(f"Quarantine failed for {node}: {e}")
