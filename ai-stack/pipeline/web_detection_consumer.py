"""
Streaming detection consumer — web traffic.

Second detector alongside detection_consumer.py (auth). This is ROADMAP rule 1
in practice: a new attack surface is a new *input view*, not a smarter model.
Same Isolation Forest, same rolling-buffer refit, same writeback schema — only
the feature set changes, from login shape (users / attempts-per-user) to web
shape (request rate / URL diversity / error ratio).

It reads the same Kafka topic as the auth consumer but with its own consumer
group, so both receive every event and filter independently:
    auth consumer  -> keeps events carrying data.srcuser / auth srcip
    web consumer   -> keeps events carrying data.url (access-log events)

Detections land in the same ai-detections-* index with source=morpheus_ai and a
distinct rule id (100002) and ai.pipeline ("web-streaming"), so the dashboard
and backend render them with no changes.

SETUP (state in the report):
  - nginx/apache on the monitored host, access log fed to Wazuh via a localfile
    block (<location>/var/log/nginx/access.log</location>, log_format apache).
  - Wazuh already ships the web-accesslog decoder; its method field is decoded
    as data.protocol (a Wazuh naming quirk), status code as data.id, path as
    data.url. This consumer falls back to parsing full_log if those are absent.
"""

import os, re, signal, sys, time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv
from kafka import KafkaConsumer
from models import get_model
from opensearchpy import OpenSearch, helpers

from consumer_common import (ai_index, decode_event, fit_evidence, heartbeat,
                             note_agent, top_agent, window_features)
# the window/feature definition, shared with the offline evaluation
from features import (WEB_FEATURES as FEATURES, WINDOW_SEC, fold_web,
                      new_web_window, web_row, window_key)

# one credential source for the whole project: dashboard/.env (git-ignored)
load_dotenv(Path(__file__).resolve().parents[2] / "dashboard" / ".env")

# ----------------------------------------------------------------- config
# Kafka's address is configurable: on a shared VM another group's broker may own
# the default port, and silently attaching to THEIR topic is worse than failing
# to connect at all, so the address in use is printed at startup.
KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092")
TOPIC          = "wazuh-archives"
SCORE_EVERY    = 60      # attempt scoring every N seconds
MIN_WINDOWS    = 10      # don't score until we have this many windows (else meaningless)
MAX_WINDOWS    = 120     # rolling buffer size (2h at 1-min windows)
CONTAMINATION  = 0.15
CONSUMER_NAME  = "web-detector"    # its status doc id in ai-pipeline-status

# inference-slot model, swappable via DETECTOR_MODEL in dashboard/.env
_MODEL = get_model(os.environ.get("DETECTOR_MODEL", "isolation_forest"))

# raw-line fallback: `IP - - [date] "GET /path HTTP/1.1" 404 512`
ACCESS_RE    = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+HTTP/[\d.]+"\s+(?P<status>\d{3})')

# ----------------------------------------------------------------- clients
consumer = KafkaConsumer(
    TOPIC,
    bootstrap_servers=KAFKA_BOOTSTRAP,
    auto_offset_reset="latest",          # only new events
    group_id="xdr-web-detector",         # distinct from the auth consumer's group
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
windows = defaultdict(new_web_window)
already_flagged = set()
consumed = 0     # every Kafka message seen
web_seen = 0     # of those, the ones that were web access events
written  = 0
STARTED_AT    = datetime.now(timezone.utc).isoformat()
last_event_at = None     # wall-clock time the last web event was folded in


def bye(*_):
    print(f"\nStopped. {consumed} messages seen, {web_seen} web events, "
          f"wrote {written} detections.")
    sys.exit(0)


signal.signal(signal.SIGINT, bye)
signal.signal(signal.SIGTERM, bye)      # docker stop


def ingest(event):
    """Fold one Wazuh web event into its time window; return True if it was one."""
    global last_event_at
    if event is None:                    # undecodable line (decode_event)
        return False
    ts = event.get("timestamp")
    if not ts:
        return False
    try:
        dt = pd.to_datetime(ts)
    except Exception:
        return False

    data = event.get("data", {})
    full_log = event.get("full_log", "") or ""

    url    = data.get("url")
    method = data.get("protocol")     # Wazuh web decoder stores the HTTP verb here
    status = data.get("id")           # HTTP response code, as a string

    if not url:                       # fall back to parsing the raw access-log line
        m = ACCESS_RE.search(full_log)
        if not m:
            return False              # not a web access event — leave it for the auth consumer
        url    = m.group("url")
        method = method or m.group("method")
        status = status or m.group("status")

    w = windows[window_key(dt)]
    fold_web(w, url, method, status, data.get("srcip"))
    note_agent(w, event)
    last_event_at = datetime.now(timezone.utc).isoformat()
    return True


def build_frame():
    """Turn accumulated windows into a feature table."""
    rows = []
    for key, w in windows.items():
        row = web_row(key, w)
        row["agent"] = top_agent(w["agents"])
        rows.append(row)
    return pd.DataFrame(rows).sort_values("timestamp") if rows else pd.DataFrame()


def categorize(r):
    """Heuristic post-classification of an anomalous web window.

    The model only says "this window deviates from baseline"; these labels turn
    that into something an analyst can triage. Pattern -> (category, MITRE, label).
    """
    # Aggregate scan shapes first: a high-volume scan can incidentally contain a
    # payload-like path, so classify by dominant behaviour before payload flags.
    if r.not_found_count >= 10 and r.distinct_urls >= 10:
        return "content_discovery", "T1595.003", "many 404s across many paths"
    if r.error_ratio >= 0.5 and r.distinct_urls >= 8:
        return "vulnerability_scan", "T1595.002", "high error rate across many paths"
    if r.post_ratio >= 0.6 and r.distinct_urls <= 3 and r.request_count >= 10:
        return "web_brute_force", "T1110", "repeated POSTs to few endpoints"
    # Targeted payload patterns (typically low-volume, specific request).
    if r.injection:
        return "web_injection", "T1190", "injection pattern in requests"
    if r.traversal:
        return "path_traversal", "T1083", "directory-traversal pattern"
    return "unclassified_anomaly", None, "unclassified deviation"


def severity(score):
    """Map anomaly score to a Wazuh-convention level (more negative = worse)."""
    if score < -0.60:
        return 12
    if score < -0.50:
        return 10
    return 7


def beat(state, result):
    """Report status to the dashboard's Pipeline page (see consumer_common)."""
    heartbeat(os_client, CONSUMER_NAME, state=state, last_result=result,
              model=_MODEL.label, lane="web", windows_buffered=len(windows),
              min_windows=MIN_WINDOWS, events_seen=web_seen,
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
        category, mitre, label = categorize(r)
        docs.append({
            "_index": index,
            "_source": {
                "timestamp": r.timestamp.isoformat(),
                "source": "morpheus_ai",
                "rule": {
                    "id": "100002",
                    "level": severity(r.score),
                    "description": f"AI: anomalous web traffic — {label}",
                },
                "ai": {
                    "model":           _MODEL.label,
                    "pipeline":        "web-streaming",
                    "anomaly_score":   float(r.score),
                    "window":          f"{WINDOW_SEC}s",
                    "event_count":     int(r.request_count),   # generic field the dashboard reads
                    "request_count":   int(r.request_count),
                    "distinct_urls":   int(r.distinct_urls),
                    "error_ratio":     float(r.error_ratio),
                    "not_found_count": int(r.not_found_count),
                    "post_ratio":      float(r.post_ratio),
                    "category":        category,
                    "mitre":           mitre,
                    "top_srcips":      [{"ip": ip, "count": n} for ip, n in r.top_ips],
                    "top_urls":        [{"url": u, "count": n} for u, n in r.top_urls],
                    # why it fired: this window vs the un-flagged ones, and the cutoff
                    "features":        window_features(r, FEATURES),
                    **evidence,
                },
                "agent": r.agent,
            },
        })

    helpers.bulk(os_client, docs)
    os_client.indices.refresh(index=index)
    written += len(docs)

    print(f"  [scorer] {len(df)} windows scored — {len(docs)} NEW detection(s) written:")
    for d in docs:
        a = d["_source"]["ai"]
        print(f"      {d['_source']['timestamp']}  score={a['anomaly_score']}  "
              f"reqs={a['request_count']}  urls={a['distinct_urls']}  err={a['error_ratio']}")
    beat("scoring", f"{len(df)} windows scored — {len(docs)} new detection(s)")


def prune():
    """Keep the buffer bounded."""
    if len(windows) > MAX_WINDOWS:
        for key in sorted(windows)[:len(windows) - MAX_WINDOWS]:
            del windows[key]


# ----------------------------------------------------------------- main loop
print(f"Consuming '{TOPIC}' (web view) from {KAFKA_BOOTSTRAP} -> {_MODEL.label} -> {ai_index()}")
print(f"Windows: {WINDOW_SEC}s | scoring every {SCORE_EVERY}s | "
      f"min {MIN_WINDOWS} windows | Ctrl-C to stop\n")
beat("starting", "connected to Kafka, waiting for events")

last_score = time.time()

while True:
    for msg in consumer:                 # yields until consumer_timeout_ms elapses
        consumed += 1
        if ingest(msg.value):
            web_seen += 1
            if web_seen % 10 == 0:
                print(f"  {web_seen} web events | {len(windows)} windows buffered")

    if time.time() - last_score >= SCORE_EVERY:
        prune()
        score_and_write()
        last_score = time.time()
