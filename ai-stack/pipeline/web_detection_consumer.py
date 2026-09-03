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

FEATURES = ["request_count", "distinct_urls", "error_ratio",
            "not_found_count", "post_ratio", "requests_per_ip", "hour"]

# raw-line fallback: `IP - - [date] "GET /path HTTP/1.1" 404 512`
ACCESS_RE    = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+HTTP/[\d.]+"\s+(?P<status>\d{3})')
INJECTION_RE = re.compile(
    r"(?i)(union\s+select|'\s*or\s*'?\s*1|<script|onerror=|\bexec\b|xp_cmdshell"
    r"|%27|%3cscript|\bsleep\(|benchmark\(|information_schema)"
)
TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e|/etc/passwd|\bboot\.ini\b|%00)")

# ----------------------------------------------------------------- clients
consumer = KafkaConsumer(
    TOPIC,
    bootstrap_servers="localhost:9092",
    auto_offset_reset="latest",          # only new events
    group_id="xdr-web-detector",         # distinct from the auth consumer's group
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
windows = defaultdict(lambda: {"count": 0, "urls": Counter(), "ips": Counter(),
                               "methods": Counter(), "statuses": Counter(),
                               "injection": False, "traversal": False})
already_flagged = set()
consumed = 0     # every Kafka message seen
web_seen = 0     # of those, the ones that were web access events
written  = 0


def bye(*_):
    print(f"\nStopped. {consumed} messages seen, {web_seen} web events, "
          f"wrote {written} detections.")
    sys.exit(0)


signal.signal(signal.SIGINT, bye)


def ingest(event):
    """Fold one Wazuh web event into its time window; return True if it was one."""
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

    key = int(dt.timestamp()) // WINDOW_SEC
    w = windows[key]
    w["count"] += 1
    w["urls"][url] += 1

    srcip = data.get("srcip")
    if srcip:
        w["ips"][srcip] += 1
    if method:
        w["methods"][method.upper()] += 1

    try:
        code = int(status)
    except (TypeError, ValueError):
        code = 0
    if code:
        w["statuses"][code] += 1

    if INJECTION_RE.search(url):
        w["injection"] = True
    if TRAVERSAL_RE.search(url):
        w["traversal"] = True

    return True


def build_frame():
    """Turn accumulated windows into a feature table."""
    rows = []
    for key, w in windows.items():
        dt = datetime.fromtimestamp(key * WINDOW_SEC, tz=timezone.utc)
        count = w["count"]
        distinct_ips = len(w["ips"])
        errors = sum(n for code, n in w["statuses"].items() if 400 <= code < 600)
        rows.append({
            "key":             key,
            "timestamp":       dt,
            "request_count":   count,
            "distinct_urls":   len(w["urls"]),
            "error_ratio":     round(errors / count, 3) if count else 0.0,
            "not_found_count": w["statuses"].get(404, 0),
            "post_ratio":      round(w["methods"].get("POST", 0) / count, 3) if count else 0.0,
            "requests_per_ip": round(count / distinct_ips, 2) if distinct_ips else count,
            "hour":            dt.hour,
            "injection":       w["injection"],
            "traversal":       w["traversal"],
            "top_ips":         w["ips"].most_common(5),
            "top_urls":        w["urls"].most_common(5),
        })
    return pd.DataFrame(rows).sort_values("timestamp") if rows else pd.DataFrame()


def categorize(r):
    """Heuristic post-classification of an anomalous web window.

    The model only says "this window deviates from baseline"; these labels turn
    that into something an analyst can triage. Pattern -> (category, MITRE, label).
    """
    if r.injection:
        return "web_injection", "T1190", "injection pattern in requests"
    if r.traversal:
        return "path_traversal", "T1083", "directory-traversal pattern"
    if r.not_found_count >= 10 and r.distinct_urls >= 10:
        return "content_discovery", "T1595.003", "many 404s across many paths"
    if r.post_ratio >= 0.6 and r.distinct_urls <= 3 and r.request_count >= 10:
        return "web_brute_force", "T1110", "repeated POSTs to few endpoints"
    if r.error_ratio >= 0.5 and r.distinct_urls >= 8:
        return "vulnerability_scan", "T1595.002", "high error rate across many paths"
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
                    "id": "100002",
                    "level": severity(r.score),
                    "description": f"AI: anomalous web traffic — {label}",
                },
                "ai": {
                    "model":           "IsolationForest",
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
              f"reqs={a['request_count']}  urls={a['distinct_urls']}  err={a['error_ratio']}")


def prune():
    """Keep the buffer bounded."""
    if len(windows) > MAX_WINDOWS:
        for key in sorted(windows)[:len(windows) - MAX_WINDOWS]:
            del windows[key]


# ----------------------------------------------------------------- main loop
print(f"Consuming '{TOPIC}' (web view) -> Isolation Forest -> {AI_INDEX}")
print(f"Windows: {WINDOW_SEC}s | scoring every {SCORE_EVERY}s | "
      f"min {MIN_WINDOWS} windows | Ctrl-C to stop\n")

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
