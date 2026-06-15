#!/usr/bin/env python3
"""Compute network baselines from Zeek conn.log exports.

The script accepts either:
- Zeek JSON log lines, or
- JSON records exported by a log shipper

It aggregates per-source metrics and writes a baseline JSON file with mean and
standard deviation fields that the Zeek policy can consume.
"""

from __future__ import annotations

import argparse
import collections
import json
import math
from dataclasses import dataclass, asdict
from pathlib import Path
from statistics import mean, pstdev
from typing import Any, Iterable


@dataclass
class MetricSummary:
    mean: float
    stddev: float


def _load_records(paths: list[Path]) -> Iterable[dict[str, Any]]:
    for path in paths:
        if not path.exists():
            continue
        with path.open() as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def _get_src_dst(record: dict[str, Any]) -> tuple[str, str]:
    src = str(record.get("id.orig_h") or record.get("src_ip") or record.get("source.ip") or "unknown")
    dst = str(record.get("id.resp_h") or record.get("dest_ip") or record.get("destination.ip") or "unknown")
    return src, dst


def _get_duration(record: dict[str, Any]) -> float:
    value = record.get("duration") or record.get("event.duration") or 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def build_baseline(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    per_src_bytes_out: dict[str, list[float]] = collections.defaultdict(list)
    per_src_unique_dst: dict[str, set[str]] = collections.defaultdict(set)
    per_src_conn_rate: dict[str, int] = collections.defaultdict(int)
    per_src_protocols: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    pair_totals: dict[str, dict[str, int]] = collections.defaultdict(lambda: collections.defaultdict(int))

    for record in records:
        src, dst = _get_src_dst(record)
        per_src_conn_rate[src] += 1
        per_src_unique_dst[src].add(dst)

        bytes_out = record.get("orig_bytes") or record.get("source.bytes") or 0
        try:
            per_src_bytes_out[src].append(float(bytes_out))
        except (TypeError, ValueError):
            per_src_bytes_out[src].append(0.0)

        proto = str(record.get("proto") or record.get("transport") or record.get("network.transport") or "unknown")
        per_src_protocols[src][proto] += 1
        pair_totals[src][dst] += 1

    baseline: dict[str, Any] = {
        "generated_at": "",
        "sources": {},
        "top_talker_pairs": {},
    }

    for src in sorted(set(per_src_conn_rate) | set(per_src_bytes_out) | set(per_src_unique_dst)):
        bytes_values = per_src_bytes_out.get(src, [0.0]) or [0.0]
        conn_count = per_src_conn_rate.get(src, 0)
        unique_dst_count = len(per_src_unique_dst.get(src, set()))
        protocol_counts = per_src_protocols.get(src, collections.Counter())
        total_protocols = sum(protocol_counts.values()) or 1

        baseline["sources"][src] = {
            "bytes_out_per_min": asdict(MetricSummary(mean=mean(bytes_values), stddev=pstdev(bytes_values) if len(bytes_values) > 1 else 0.0)),
            "unique_destinations_per_min": asdict(MetricSummary(mean=float(unique_dst_count), stddev=0.0)),
            "connection_rate_per_min": asdict(MetricSummary(mean=float(conn_count), stddev=0.0)),
            "protocol_distribution": {
                proto: round(count / total_protocols, 4)
                for proto, count in protocol_counts.items()
            },
        }

        top_pairs = sorted(pair_totals.get(src, {}).items(), key=lambda item: item[1], reverse=True)
        baseline["top_talker_pairs"][src] = [
            {"dst": dst, "count": count}
            for dst, count in top_pairs[:10]
        ]

    return baseline


def main() -> int:
    parser = argparse.ArgumentParser(description="Compute Zeek conn.log baselines for the HPC simulator")
    parser.add_argument("--input", nargs="+", required=True, help="Input conn.log / JSON log files")
    parser.add_argument("--output", required=True, help="Output baseline JSON path")
    args = parser.parse_args()

    input_paths = [Path(path) for path in args.input]
    records = list(_load_records(input_paths))
    baseline = build_baseline(records)
    baseline["generated_at"] = __import__("datetime").datetime.utcnow().isoformat() + "Z"

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(baseline, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
