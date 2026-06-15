#!/usr/bin/env python3
"""Detect beaconing from Zeek conn.log data.

The detector scans a conn.log export, groups connections by source/destination
pair, and raises an alert when repeated low-variance inter-arrival timing and
low bandwidth point to potential C2 keepalive traffic.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from statistics import pstdev
from typing import Any


@dataclass
class BeaconAlert:
    source: str
    destination: str
    connection_count: int
    stddev_seconds: float
    mean_bytes: float
    reason: str


def _load_records(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records

    with path.open() as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def detect_beaconing(records: list[dict[str, Any]]) -> list[BeaconAlert]:
    pair_times: dict[tuple[str, str], list[float]] = defaultdict(list)
    pair_bytes: dict[tuple[str, str], list[float]] = defaultdict(list)

    for record in records:
        src = str(record.get("id.orig_h") or record.get("src_ip") or "unknown")
        dst = str(record.get("id.resp_h") or record.get("dest_ip") or "unknown")
        ts = record.get("ts") or record.get("timestamp") or 0
        try:
            ts_value = float(ts)
        except (TypeError, ValueError):
            try:
                ts_value = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
            except ValueError:
                ts_value = 0.0

        orig_bytes = record.get("orig_bytes") or record.get("bytes_out") or 0
        try:
            bytes_out = float(orig_bytes)
        except (TypeError, ValueError):
            bytes_out = 0.0

        key = (src, dst)
        pair_times[key].append(ts_value)
        pair_bytes[key].append(bytes_out)

    alerts: list[BeaconAlert] = []
    for (src, dst), stamps in pair_times.items():
        if len(stamps) <= 10:
            continue

        stamps = sorted(stamps)
        gaps = [stamps[index] - stamps[index - 1] for index in range(1, len(stamps)) if stamps[index] >= stamps[index - 1]]
        if len(gaps) < 5:
            continue

        stddev_seconds = pstdev(gaps)
        mean_bytes = sum(pair_bytes[(src, dst)]) / max(len(pair_bytes[(src, dst)]), 1)

        if stddev_seconds < 5.0 and len(stamps) > 10:
            reason = "Low-variance periodic traffic pattern consistent with beaconing"
            if mean_bytes < 1024:
                reason += " and low-bandwidth keepalive behavior"
            alerts.append(BeaconAlert(
                source=src,
                destination=dst,
                connection_count=len(stamps),
                stddev_seconds=stddev_seconds,
                mean_bytes=mean_bytes,
                reason=reason,
            ))

    return alerts


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect beaconing from Zeek conn.log")
    parser.add_argument("--input", required=True, help="Path to conn.log or JSON export")
    parser.add_argument("--output", required=True, help="Output JSON file for beaconing alerts")
    args = parser.parse_args()

    records = _load_records(Path(args.input))
    alerts = [asdict(alert) for alert in detect_beaconing(records)]

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"generated_at": datetime.utcnow().isoformat() + "Z", "alerts": alerts}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
