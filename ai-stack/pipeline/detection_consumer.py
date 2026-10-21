"""
Streaming detection consumer.

Reads Wazuh archive events from Kafka, aggregates them into time windows,
runs Isolation Forest over the accumulated windows, and writes flagged windows
back to OpenSearch as AI detections (source=morpheus_ai, rule ID 100001).

This is the CPU-equivalent of the Morpheus streaming pipeline stage:
    Kafka source -> deserialize -> preprocess/feature-build -> inference -> writeback

DESIGN NOTE (state this in the report):
Isolation Forest is refit over a rolling buffer of recent windows rather than
loading a pre-trained baseline. NVIDIA's DFP separates training and inference into
two pipelines communicating through a model store; here both happen in one process
because the dataset is small and the baseline is short-lived. The architecture is
equivalent; the separation is a scale concern, not a correctness one.
"""

import os, signal, sys, time
from collections import defaultdict
from pathlib import Path

from dotenv import load_dotenv

# one credential source for the whole project: dashboard/.env (git-ignored)
load_dotenv(Path(__file__).resolve().parents[2] / "dashboard" / ".env")
from datetime import datetime, timezone

import pandas as pd
from kafka import KafkaConsumer
from models import get_model
from opensearchpy import OpenSearch, helpers

from consumer_common import (ai_index, decode_event, fit_evidence, heartbeat,
                             note_agent, top_agent)
# the window/feature definition, shared with the offline evaluation
from features import (AUTH_FEATURES as FEATURES, WINDOW_SEC, auth_row,
                      fold_auth, new_auth_window, window_key)
# event reading + detection document, shared with the Morpheus pipeline
from auth_lane import detection_doc, parse_auth_event

# ----------------------------------------------------------------- config
# Kafka's address is configurable: on a shared VM another group's broker may own
# the default port, and silently attaching to THEIR topic is worse than failing
# to connect at all, so the address in use is printed at startup.
KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092")
TOPIC          = "wazuh-archives"
SCORE_EVERY    = 60      # attempt scoring every N seconds
MIN_WINDOWS    = int(os.environ.get("MIN_WINDOWS", "10"))  # don't score until this many windows (else meaningless); lower only for a demo
MAX_WINDOWS    = 120     # rolling buffer size (2h at 1-min windows)
CONTAMINATION  = 0.15
CONSUMER_NAME  = "auth-detector"   # its status doc id in ai-pipeline-status

# inference-slot model, swappable via DETECTOR_MODEL in dashboard/.env
_MODEL = get_model(os.environ.get("DETECTOR_MODEL", "isolation_forest"))

# ----------------------------------------------------------------- clients
consumer = KafkaConsumer(
    TOPIC,
    bootstrap_servers=KAFKA_BOOTSTRAP,
    auto_offset_reset="latest",          # only new events
    group_id="xdr-detector",
    consumer_timeout_ms=1000,            # so the loop can breathe and score on schedule
    value_deserializer=decode_event,     # None for a line that isn't JSON
)

os_client = OpenSearch(
    hosts=[{"host": os.environ.get("OS_HOST", "localhost"),
            "port": int(os.environ.get("OS_PORT", "9200"))}],
    http_auth=(os.environ.get("OS_USER", "admin"), os.environ.get("OS_PASS", "")),
    use_ssl=True, verify_certs=False, ssl_show_warn=False,
)

# ----------------------------------------------------------------- state
# window_key (epoch // WINDOW_SEC) -> accumulated stats
windows = defaultdict(new_auth_window)
already_flagged = set()
consumed = 0
written  = 0
STARTED_AT    = datetime.now(timezone.utc).isoformat()
last_event_at = None     # wall-clock time the last auth event was folded in


def bye(*_):
    print(f"\nStopped. consumed={consumed} events, wrote={written} detections.")
    sys.exit(0)


signal.signal(signal.SIGINT, bye)
signal.signal(signal.SIGTERM, bye)      # docker stop


def ingest(event):
    """Fold one Wazuh event into its time window."""
    global last_event_at
    ev = parse_auth_event(event)
    if ev is None:
        return

    w = windows[window_key(ev.dt)]
    fold_auth(w, ev.srcip, ev.level, ev.user)
    note_agent(w, event)
    last_event_at = datetime.now(timezone.utc).isoformat()


def build_frame():
    """Turn accumulated windows into a feature table."""
    rows = []
    for key, w in windows.items():
        row = auth_row(key, w)
        row["agent"] = top_agent(w["agents"])
        rows.append(row)
    return pd.DataFrame(rows).sort_values("timestamp") if rows else pd.DataFrame()


def beat(state, result):
    """Report status to the dashboard's Pipeline page (see consumer_common)."""
    heartbeat(os_client, CONSUMER_NAME, state=state, last_result=result,
              model=_MODEL.label, lane="auth", windows_buffered=len(windows),
              min_windows=MIN_WINDOWS, events_seen=consumed,
              detections_written=written, last_event_at=last_event_at,
              started_at=STARTED_AT, score_every_sec=SCORE_EVERY,
              kafka_bootstrap=KAFKA_BOOTSTRAP, topic=TOPIC, index=ai_index())


def score_and_write():
    """Fit IF over the rolling buffer and write newly flagged windows."""
    global written

    df = build_frame()
    if len(df) < MIN_WINDOWS:
        print(f"  [scorer] {len(df)}/{MIN_WINDOWS} windows — not enough to score yet")
        beat("warming_up", f"{len(df)}/{MIN_WINDOWS} windows buffered — not enough to score yet")
        return

    X = df[FEATURES]
    # inference slot — model chosen by DETECTOR_MODEL (see models/ registry)
    df["flag"], df["score"] = _MODEL.fit_score(X, CONTAMINATION)
    evidence = fit_evidence(df, FEATURES)

    hits = df[(df.flag == -1) & (~df.key.isin(already_flagged))]
    if hits.empty:
        print(f"  [scorer] {len(df)} windows scored — no new anomalies")
        beat("scoring", f"{len(df)} windows scored — no new anomalies")
        return

    index = ai_index()
    docs = []
    for _, r in hits.iterrows():
        already_flagged.add(r.key)
        docs.append(detection_doc(r, index, _MODEL.label, "kafka-streaming",
                                  FEATURES, evidence))

    helpers.bulk(os_client, docs)
    os_client.indices.refresh(index=index)
    written += len(docs)

    print(f"  [scorer] {len(df)} windows scored — {len(docs)} NEW detection(s) written:")
    for d in docs:
        a = d["_source"]["ai"]
        print(f"      {d['_source']['timestamp']}  score={a['anomaly_score']}  "
              f"events={a['event_count']}  users={a['distinct_users']}")
    beat("scoring", f"{len(df)} windows scored — {len(docs)} new detection(s)")


def prune():
    """Keep the buffer bounded."""
    if len(windows) > MAX_WINDOWS:
        for key in sorted(windows)[:len(windows) - MAX_WINDOWS]:
            del windows[key]


# ----------------------------------------------------------------- main loop
print(f"Consuming '{TOPIC}' from {KAFKA_BOOTSTRAP} -> {_MODEL.label} -> {ai_index()}")
print(f"Windows: {WINDOW_SEC}s | scoring every {SCORE_EVERY}s | "
      f"min {MIN_WINDOWS} windows | Ctrl-C to stop\n")
beat("starting", "connected to Kafka, waiting for events")

last_score = time.time()

while True:
    for msg in consumer:                 # yields until consumer_timeout_ms elapses
        ingest(msg.value)
        consumed += 1
        if consumed % 10 == 0:
            print(f"  consumed {consumed} events | {len(windows)} windows buffered")

    if time.time() - last_score >= SCORE_EVERY:
        prune()
        score_and_write()
        last_score = time.time()
