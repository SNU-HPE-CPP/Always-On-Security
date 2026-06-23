#!/bin/bash
# Rebuilds the Always-On Security containers, starts them, and automatically captures the new baseline image digests.
# Run this instead of 'docker compose up' when you want to rebuild the images.

set -e

echo "[1/3] Building and starting containers (Detached)..."
docker compose up -d --build

echo "[2/3] Waiting for nodes to be available in docker..."
for node in node1 node2 node3 node4; do
    until docker inspect $node >/dev/null 2>&1; do
        sleep 2
    done
done

# Give it extra time to ensure containers are fully running and tags are applied
sleep 5

echo ""
echo "[3/4] Capturing new image baselines to prevent IMAGE_MISMATCH alerts..."
.venv/bin/python3 scripts/capture_approved_images.py

echo "[4/4] Updating configuration baseline hashes..."
.venv/bin/python3 generate_baseline.py --config-dir ./risk_engine/config --service-files rules.yaml,master_config.yaml,fast_path_policy.yaml,approved_images.yaml,runtime_baseline.yaml

echo "Restarting host-observer to pick up new baselines..."
docker compose restart host-observer

echo "✅ Baseline capture complete! Environment is secured."
echo ""

echo "Attaching to logs..."
docker compose logs -f
