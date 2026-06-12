#!/usr/bin/env bash
set -euo pipefail

SURICATA_INTERFACE="${SURICATA_INTERFACE:-eth0}"
ZEEK_INTERFACE="${ZEEK_INTERFACE:-eth0}"
ZEEK_SCRIPT="${ZEEK_SCRIPT:-/opt/security-monitor/zeek/hpc_monitor.zeek}"
ZEEK_EMULATOR="${ZEEK_EMULATOR:-/opt/security-monitor/zeek/zeek_emulator.py}"
SURICATA_CONFIG="${SURICATA_CONFIG:-/opt/security-monitor/suricata/suricata.yaml}"
FILEBEAT_CONFIG="${FILEBEAT_CONFIG:-/opt/security-monitor/filebeat.yml}"

mkdir -p /var/log/security /var/log/zeek /var/log/suricata
mkdir -p /etc/suricata/rules

cp /opt/security-monitor/suricata/hpc-scan.rules /etc/suricata/rules/hpc-scan.rules
cp /opt/security-monitor/suricata/threshold.conf /etc/suricata/threshold.conf

suricata -i "${SURICATA_INTERFACE}" -c "${SURICATA_CONFIG}" -l /var/log/suricata >/var/log/security/suricata.stdout 2>&1 &
SURICATA_PID=$!

python3 "${ZEEK_EMULATOR}" >/var/log/security/zeek.stdout 2>&1 &
ZEEK_PID=$!

if command -v filebeat >/dev/null 2>&1; then
  filebeat -e -c "${FILEBEAT_CONFIG}" >/var/log/security/filebeat.stdout 2>&1 &
  FILEBEAT_PID=$!
else
  echo "filebeat binary not present; continuing with Zeek/Suricata only" | tee -a /var/log/security/filebeat.stdout
  FILEBEAT_PID=""
fi

term_handler() {
  kill "${SURICATA_PID}" "${ZEEK_PID}" ${FILEBEAT_PID:-} >/dev/null 2>&1 || true
}
trap term_handler INT TERM

wait -n "${SURICATA_PID}" "${ZEEK_PID}" ${FILEBEAT_PID:-}
