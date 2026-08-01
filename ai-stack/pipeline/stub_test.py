"""Dummy producer + consumer. No ML. Proves messages flow through Kafka."""
from kafka import KafkaProducer, KafkaConsumer
import json, time

TOPIC = "wazuh-archives"

producer = KafkaProducer(
    bootstrap_servers="localhost:9092",
    value_serializer=lambda v: json.dumps(v).encode(),
)
for i in range(5):
    msg = {"n": i, "note": "stub message", "ts": time.time()}
    producer.send(TOPIC, msg)
    print("sent:", msg)
producer.flush()

consumer = KafkaConsumer(
    TOPIC,
    bootstrap_servers="localhost:9092",
    auto_offset_reset="earliest",
    consumer_timeout_ms=5000,          # stop after 5s of silence
    value_deserializer=lambda v: json.loads(v.decode()),
)
print("\n--- reading back ---")
for m in consumer:
    print("got:", m.value)
print("done")
