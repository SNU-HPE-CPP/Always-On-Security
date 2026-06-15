#!/usr/bin/env python3
"""Zeek-compatible shim for the local Docker HPC simulation.

The upstream Zeek package is not available in the current apt metadata, so this
shim provides a buildable fallback that emits notices derived from the same
static policy used by the Zeek script. It does not sniff packets; instead it
creates a lightweight local event stream that keeps the container lifecycle and
log shipping paths working in air-gapped lab setups.
"""

from __future__ import annotations

import json
import os
import socket
import time
from datetime import datetime
from pathlib import Path

import psutil

SERVICE_ALLOWLIST = {
    "compute-net": {22, 50000, 50001, 50002},
    "storage-net": {22, 2049},
    "mgmt-net": {22, 5514, 5555, 5556},  # 5514 = wazuh mock syslog (non-root)
}

EXPECTED_PORTS = {22, 2049, 5514, 5555, 5556, 50000, 50001, 50002}


def _emit(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def _local_ips() -> set[str]:
    ips = {"127.0.0.1"}
    try:
        for entry in psutil.net_if_addrs().values():
            for addr in entry:
                if getattr(addr, "address", None):
                    ips.add(addr.address)
    except Exception:
        pass
    return ips


def main() -> int:
    out_dir = Path(os.getenv("ZEEK_OUT_DIR", "/var/log/zeek"))
    notice_path = out_dir / "notice.log"
    conn_path = out_dir / "conn.log"

    hostname = socket.gethostname()
    local_ips = sorted(_local_ips())

    boot = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "host": hostname,
        "notice": "Zeek shim started",
        "local_ips": local_ips,
        "type": "zeek_notice",
    }
    _emit(notice_path, boot)

    # Emit a periodic heartbeat plus a summary of suspicious local listeners.
    while True:
        try:
            listeners = []
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status != psutil.CONN_LISTEN or not conn.laddr:
                    continue
                port = int(conn.laddr.port)
                if port not in EXPECTED_PORTS:
                    listeners.append({"port": port, "pid": conn.pid})

            if listeners:
                _emit(notice_path, {
                    "ts": datetime.utcnow().isoformat() + "Z",
                    "host": hostname,
                    "notice": "Unexpected listening ports detected",
                    "listeners": listeners,
                    "type": "zeek_notice",
                })

            _emit(conn_path, {
                "ts": datetime.utcnow().isoformat() + "Z",
                "host": hostname,
                "type": "zeek_conn",
                "pairs": [],
                "allowlist": {k: sorted(v) for k, v in SERVICE_ALLOWLIST.items()},
            })

        except Exception as exc:
            _emit(notice_path, {
                "ts": datetime.utcnow().isoformat() + "Z",
                "host": hostname,
                "notice": f"Zeek shim error: {exc}",
                "type": "zeek_notice",
            })

        time.sleep(10)


if __name__ == "__main__":
    raise SystemExit(main())
