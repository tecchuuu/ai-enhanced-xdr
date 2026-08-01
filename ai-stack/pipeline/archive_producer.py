"""
Streams Wazuh archive events into Kafka.

Substitutes for Filebeat because Filebeat supports only one output at a time and
is already shipping to the Wazuh indexer. Production equivalent = a second Filebeat
instance with a Kafka output.

Handles UTC date rollover: Wazuh writes archives to a per-day file
(archives/YYYY/Mon/ossec-archive-DD.json) and rotates at UTC midnight (07:00 local
for UTC+7). The producer re-derives the filename and re-attaches automatically,
so it can run indefinitely without silently going deaf after the rotation.
"""

import json
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

from kafka import KafkaProducer

TOPIC = "wazuh-archives"
CONTAINER = "single-node-wazuh.manager-1"

producer = KafkaProducer(
    bootstrap_servers="localhost:9092",
    value_serializer=lambda v: json.dumps(v).encode(),
)

sent = 0
skipped = 0
proc = None


def current_archive():
    """Path of the archive file Wazuh is writing to right now (UTC-based)."""
    d = datetime.now(timezone.utc)
    return f"/var/ossec/logs/archives/{d:%Y}/{d:%b}/ossec-archive-{d:%d}.json"


def bye(*_):
    print(f"\nStopped. {sent} events published, {skipped} unparseable lines skipped.")
    try:
        producer.flush()
        if proc:
            proc.terminate()
    finally:
        sys.exit(0)


signal.signal(signal.SIGINT, bye)
signal.signal(signal.SIGTERM, bye)

print(f"Publishing Wazuh archive events to Kafka topic '{TOPIC}'")
print(f"Container: {CONTAINER}   (Ctrl-C to stop)")

while True:
    path = current_archive()
    day = datetime.now(timezone.utc).day
    print(f"\n[{datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC] tailing {path}")

    # -n 0 = only new lines from this point on, not the whole existing file
    proc = subprocess.Popen(
        ["docker", "exec", CONTAINER, "tail", "-F", "-n", "0", path],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    for line in proc.stdout:
        line = line.strip()
        if line:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            producer.send(TOPIC, event)
            sent += 1

            rule = event.get("rule", {})
            data = event.get("data", {})
            tag = f"rule {rule.get('id')} lvl {rule.get('level')}" if rule else "no rule"
            who = (data.get("srcuser")
                   or data.get("srcip")
                   or event.get("decoder", {}).get("name", "?"))
            print(f"[{sent:5d}] -> kafka  {tag:22s} {who}", flush=True)

        # UTC day rolled over -> Wazuh is now writing to a new file, re-attach
        if datetime.now(timezone.utc).day != day:
            print(f"[{datetime.now(timezone.utc):%H:%M} UTC] date rollover — switching file")
            proc.terminate()
            break

    # tail died (rotation, container restart, etc.) — pause then re-attach
    producer.flush()
    time.sleep(2)
