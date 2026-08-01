#!/bin/bash
source /root/ml-venv/bin/activate
mkdir -p /root/logs

cd /root/xdr-dashboard
nohup uvicorn main:app --host 0.0.0.0 --port 8000 > /root/logs/api.log 2>&1 &
nohup python3 -m http.server 8080 > /root/logs/web.log 2>&1 &

cd /root/ai-stack/pipeline
nohup python archive_producer.py   > /root/logs/producer.log 2>&1 &
nohup python detection_consumer.py > /root/logs/consumer.log 2>&1 &

sleep 2
echo "started:"; jobs -l
echo "logs in /root/logs/  |  stop with: pkill -f 'uvicorn|http.server|archive_producer|detection_consumer'"
