import threading
import logging
from pathlib import Path

import yaml
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

log = logging.getLogger(__name__)


class RuleEngine:
    def __init__(self, rules_path: str):
        self._path = Path(rules_path)
        self._rules: list = []
        self._lock = threading.RLock()
        self._load()
        self._start_watcher()

    @classmethod
    def from_yaml(cls, path: str) -> "RuleEngine":
        return cls(path)

    def _load(self) -> None:
        try:
            with open(self._path) as f:
                rules = yaml.safe_load(f) or []
            with self._lock:
                self._rules = rules
            log.info(f"Loaded {len(rules)} rules from {self._path}")
        except Exception as e:
            log.error(f"Failed to load rules: {e}")

    def _start_watcher(self) -> None:
        handler = _ReloadHandler(self._load, self._path.name)
        self._observer = Observer()
        self._observer.schedule(handler, str(self._path.parent), recursive=False)
        self._observer.daemon = True
        self._observer.start()
        log.info(f"Watching {self._path.parent} for rule changes")

    def match(self, event: dict) -> list[tuple[str, int, int]]:
        reasons_str = " ".join(event.get("reasons", []))
        matches = []
        with self._lock:
            for rule in self._rules:
                cond = rule.get("match", {})
                substr = cond.get("reasons_contains")
                if substr and substr in reasons_str:
                    matches.append((
                        rule["id"],
                        int(rule.get("severity", 0)),
                        int(rule.get("blast_radius", 0)),
                    ))
        return matches


class _ReloadHandler(FileSystemEventHandler):
    def __init__(self, callback, filename: str):
        self._callback = callback
        self._filename = filename

    def on_modified(self, event):
        if not event.is_directory and Path(event.src_path).name == self._filename:
            log.info(f"Rule file changed — hot-reloading")
            self._callback()
