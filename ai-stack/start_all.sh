#!/bin/bash
# Starts the AI-XDR pipeline + dashboard backend. Paths are derived from this
# script's location, so it works wherever the repo is checked out.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$ROOT/ml-venv/bin"
LOGS="$ROOT/logs"
mkdir -p "$LOGS"

cd "$ROOT/dashboard"
nohup "$VENV/uvicorn" main:app --host 0.0.0.0 --port 8000 > "$LOGS/api.log" 2>&1 &

cd "$ROOT/ai-stack/pipeline"
nohup "$VENV/python" -u archive_producer.py   > "$LOGS/producer.log" 2>&1 &
nohup "$VENV/python" -u detection_consumer.py > "$LOGS/consumer.log" 2>&1 &

# web detector — enable once nginx access logs are fed to Wazuh (see the module
# docstring). Runs alongside the auth consumer on its own Kafka consumer group.
# nohup "$VENV/python" -u web_detection_consumer.py > "$LOGS/web_consumer.log" 2>&1 &

sleep 2
echo "started:"; jobs -l
echo "logs in $LOGS/  |  stop with: pkill -f 'uvicorn|archive_producer|detection_consumer|web_detection_consumer'"
echo "frontend: cd $ROOT/dashboard/frontend && npm run dev"
