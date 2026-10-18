#!/bin/bash
# One-shot demo run on the SIAM VM: stack up -> pipeline up -> attack in the
# background. Safe to log out after it prints "launched"; everything keeps
# running server-side. Uses the host ports from wazuh/.env and ai-stack/.env
# (SETUP.md section 0), so it does not collide with the other group.
set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p logs

echo "[1/4] Wazuh stack"
(cd wazuh && docker compose -p luckyfive_wazuh up -d)

echo "[2/4] waiting for the indexer to go green (up to ~3 min)"
PASS="$(grep '^INDEXER_PASSWORD=' wazuh/.env | cut -d= -f2-)"
PORT="$(grep '^INDEXER_PORT=' wazuh/.env | cut -d= -f2-)"
for _ in $(seq 1 36); do
  if curl -sk -u "admin:$PASS" "https://localhost:${PORT:-9200}/_cluster/health" | grep -q '"status":"green"'; then
    echo "      green"; break
  fi
  sleep 5
done

echo "[3/4] Kafka, Filebeat, detectors, API (fresh detectors, no state from earlier runs)"
# Processes from before the move to containers (start_all.sh, ml-venv) would
# hold port 8000 and double-consume Kafka. Only ours: matched by this repo's path.
pkill -f "$ROOT/ml-venv/bin/(uvicorn|python -u (archive_producer|detection_consumer|web_detection_consumer))" 2>/dev/null || true
# --build: rebuilds the image if the code changed since last time (cached otherwise)
(cd ai-stack && docker compose -p luckyfive_kafka -f ai-stack.yml up -d --build \
  && docker compose -p luckyfive_kafka -f ai-stack.yml restart auth-detector web-detector)
sleep 10

echo "[4/4] attack in the background (~15 min)"
nohup bash scripts/demo_attack.sh > logs/attack.log 2>&1 &

echo
echo "launched. You can log out now."
echo "In ~15 min, log back in and run:"
echo "  cd $ROOT && cat logs/attack.log && docker logs luckyfive_kafka-auth-detector-1 2>&1 | grep -A3 'NEW detection'"
