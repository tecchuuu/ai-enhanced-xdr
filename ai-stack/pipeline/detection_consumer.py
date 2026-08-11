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

import json, re, signal, sys, time
from collections import Counter, defaultdict
from datetime import datetime, timezone

import pandas as pd
from kafka import KafkaConsumer
from sklearn.ensemble import IsolationForest
from opensearchpy import OpenSearch, helpers

# ----------------------------------------------------------------- config
TOPIC          = "wazuh-archives"
WINDOW_SEC     = 60      # aggregate events into 1-minute windows
SCORE_EVERY    = 60      # attempt scoring every N seconds
MIN_WINDOWS    = 10      # don't score until we have this many windows (else meaningless)
MAX_WINDOWS    = 120     # rolling buffer size (2h at 1-min windows)
CONTAMINATION  = 0.15
AI_INDEX       = f"ai-detections-{datetime.now(timezone.utc):%Y.%m.%d}"

FEATURES = ["event_count", "distinct_users", "max_level",
            "hour", "events_per_user"]

USER_RE = re.compile(r"(?:invalid user |user )([A-Za-z0-9_.-]+)")

# ----------------------------------------------------------------- clients
consumer = KafkaConsumer(
    TOPIC,
    bootstrap_servers="localhost:9092",
    auto_offset_reset="latest",          # only new events
    group_id="xdr-detector",
    consumer_timeout_ms=1000,            # so the loop can breathe and score on schedule
    value_deserializer=lambda v: json.loads(v.decode()),
)

os_client = OpenSearch(
    hosts=[{"host": "localhost", "port": 9200}],
    http_auth=("admin", "SecretPassword"),
    use_ssl=True, verify_certs=False, ssl_show_warn=False,
)

# ----------------------------------------------------------------- state
# window_key (epoch // WINDOW_SEC) -> accumulated stats
windows = defaultdict(lambda: {"count": 0, "users": set(), "ips": Counter(),
                               "max_level": 0})
already_flagged = set()
consumed = 0
written  = 0


def bye(*_):
    print(f"\nStopped. consumed={consumed} events, wrote={written} detections.")
    sys.exit(0)


signal.signal(signal.SIGINT, bye)


def ingest(event):
    """Fold one Wazuh event into its time window."""
    ts = event.get("timestamp")
    if not ts:
        return
    try:
        dt = pd.to_datetime(ts)
    except Exception:
        return

    data = event.get("data", {})
    # only authentication-relevant events carry srcip; skip the rest
    if "srcip" not in data:
        return

    key = int(dt.timestamp()) // WINDOW_SEC
    w = windows[key]
    w["count"] += 1
    w["max_level"] = max(w["max_level"], event.get("rule", {}).get("level", 0) or 0)
    w["ips"][data["srcip"]] += 1

    user = data.get("srcuser")
    if not user:
        m = USER_RE.search(event.get("full_log", "") or "")
        user = m.group(1) if m else None
    if user:
        w["users"].add(user)


def build_frame():
    """Turn accumulated windows into a feature table."""
    rows = []
    for key, w in windows.items():
        dt = datetime.fromtimestamp(key * WINDOW_SEC, tz=timezone.utc)
        users = len(w["users"])
        rows.append({
            "key":             key,
            "timestamp":       dt,
            "event_count":     w["count"],
            "distinct_users":  users,
            "max_level":       w["max_level"],
            "hour":            dt.hour,
            "events_per_user": round(w["count"] / users, 2) if users else w["count"],
            "top_ips":         w["ips"].most_common(5),
        })
    return pd.DataFrame(rows).sort_values("timestamp") if rows else pd.DataFrame()


def categorize(r):
    """Heuristic post-classification of an anomalous window.

    The model only says "this window deviates from baseline"; these labels turn
    that into something an analyst can triage. Pattern -> (category, MITRE, label).
    """
    if r.events_per_user >= 10 and r.distinct_users <= 3:
        return "brute_force", "T1110.001", "brute-force pattern"
    if r.distinct_users >= 5 and r.events_per_user <= 5:
        return "password_spraying", "T1110.003", "password-spraying pattern"
    if r.hour < 6 or r.hour >= 22:
        return "suspicious_timing", "T1078", "off-hours activity"
    return "unclassified_anomaly", None, "unclassified deviation"


def severity(score):
    """Map anomaly score to a Wazuh-convention level (more negative = worse)."""
    if score < -0.60:
        return 12
    if score < -0.50:
        return 10
    return 7


def score_and_write():
    """Fit IF over the rolling buffer and write newly flagged windows."""
    global written

    df = build_frame()
    if len(df) < MIN_WINDOWS:
        print(f"  [scorer] {len(df)}/{MIN_WINDOWS} windows — not enough to score yet")
        return

    model = IsolationForest(contamination=CONTAMINATION, random_state=42)
    X = df[FEATURES]
    df["flag"]  = model.fit_predict(X)
    df["score"] = model.score_samples(X).round(4)

    hits = df[(df.flag == -1) & (~df.key.isin(already_flagged))]
    if hits.empty:
        print(f"  [scorer] {len(df)} windows scored — no new anomalies")
        return

    docs = []
    for _, r in hits.iterrows():
        already_flagged.add(r.key)
        category, mitre, label = categorize(r)
        docs.append({
            "_index": AI_INDEX,
            "_source": {
                "timestamp": r.timestamp.isoformat(),
                "source": "morpheus_ai",
                "rule": {
                    "id": "100001",
                    "level": severity(r.score),
                    "description": f"AI: anomalous authentication behaviour — {label}",
                },
                "ai": {
                    "model":           "IsolationForest",
                    "pipeline":        "kafka-streaming",
                    "anomaly_score":   float(r.score),
                    "window":          f"{WINDOW_SEC}s",
                    "event_count":     int(r.event_count),
                    "distinct_users":  int(r.distinct_users),
                    "events_per_user": float(r.events_per_user),
                    "category":        category,
                    "mitre":           mitre,
                    "top_srcips":      [{"ip": ip, "count": n} for ip, n in r.top_ips],
                },
                "agent": {"name": "ubuntu-vm"},
            },
        })

    helpers.bulk(os_client, docs)
    os_client.indices.refresh(index=AI_INDEX)
    written += len(docs)

    print(f"  [scorer] {len(df)} windows scored — {len(docs)} NEW detection(s) written:")
    for d in docs:
        a = d["_source"]["ai"]
        print(f"      {d['_source']['timestamp']}  score={a['anomaly_score']}  "
              f"events={a['event_count']}  users={a['distinct_users']}")


def prune():
    """Keep the buffer bounded."""
    if len(windows) > MAX_WINDOWS:
        for key in sorted(windows)[:len(windows) - MAX_WINDOWS]:
            del windows[key]


# ----------------------------------------------------------------- main loop
print(f"Consuming '{TOPIC}' -> Isolation Forest -> {AI_INDEX}")
print(f"Windows: {WINDOW_SEC}s | scoring every {SCORE_EVERY}s | "
      f"min {MIN_WINDOWS} windows | Ctrl-C to stop\n")

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
