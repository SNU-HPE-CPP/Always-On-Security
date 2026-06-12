FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    iproute2 \
    iptables \
    jq \
    python3 \
    python3-psutil \
    suricata \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY . /opt/security-monitor
WORKDIR /opt/security-monitor

CMD ["/opt/security-monitor/start.sh"]
