"""
Takes Isolation Forest results on real auth windows and writes flagged
anomalies into OpenSearch as AI detections, tagged source=ai.
This is the writeback loop from project_plan.md.
"""
import json, re
import pandas as pd
from sklearn.ensemble import IsolationForest
from opensearchpy import OpenSearch, helpers

ARCHIVE   = "/home/magi/root-backup/archive_18.json"
WINDOW    = "1min"
AI_INDEX  = "ai-detections-2026.07.18"

client = OpenSearch(
    hosts=[{"host": "localhost", "port": 9200}],
    http_auth=("admin", "SecretPassword"),
    use_ssl=True, verify_certs=False, ssl_show_warn=False,
)

# ---- load + window (same logic as your model script) ----
USER_RE = re.compile(r"(?:invalid user |user )([A-Za-z0-9_.-]+)")
rows = []
for line in open(ARCHIVE):
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        continue
    d = e.get("data", {})
    if "srcip" not in d:
        continue
    r = e.get("rule", {})
    user = d.get("srcuser")
    if not user:
        m = USER_RE.search(e.get("full_log", "") or "")
        user = m.group(1) if m else None
    rows.append({"timestamp": e.get("timestamp"), "rule_id": r.get("id"),
                 "level": r.get("level", 0), "srcuser": user, "srcip": d.get("srcip")})

df = pd.DataFrame(rows)
df["timestamp"] = pd.to_datetime(df["timestamp"])
df = df.set_index("timestamp").sort_index()

w = df.resample(WINDOW).agg(
    event_count=("rule_id", "size"),
    distinct_users=("srcuser", "nunique"),
    max_level=("level", "max"),
).fillna(0)
w["hour"] = w.index.hour
w["events_per_user"] = (w.event_count / w.distinct_users.replace(0, 1)).round(2)

FEATURES = ["event_count", "distinct_users", "max_level", "hour", "events_per_user"]
model = IsolationForest(contamination=0.15, random_state=42)
w["anomaly"] = model.fit_predict(w[FEATURES])
w["score"] = model.score_samples(w[FEATURES]).round(4)   # lower = more anomalous

flagged = w[(w.anomaly == -1) & (w.event_count > 0)]
print(f"Model flagged {len(flagged)} anomalous windows\n")

# ---- write flagged windows back as AI detections ----
docs = []
for ts, row in flagged.iterrows():
    docs.append({
        "_index": AI_INDEX,
        "_source": {
            "timestamp":   ts.isoformat(),
            "source":      "morpheus_ai",          # the tag that separates AI from rule
            "rule": {                              # 100000+ range per project_plan.md
                "id": "100001",
                "level": 10,
                "description": "AI: anomalous authentication behaviour detected",
            },
            "ai": {
                "model":          "IsolationForest",
                "anomaly_score":  float(row.score),
                "window":         WINDOW,
                "event_count":    int(row.event_count),
                "distinct_users": int(row.distinct_users),
                "events_per_user": float(row.events_per_user),
            },
            "agent": {"name": "ubuntu-vm"},
        },
    })

if docs:
    helpers.bulk(client, docs)
    client.indices.refresh(index=AI_INDEX)
    print(f"Wrote {len(docs)} AI detections -> {AI_INDEX}")
    for d in docs:
        s = d["_source"]
        print(f"  {s['timestamp']}  score={s['ai']['anomaly_score']}  "
              f"events={s['ai']['event_count']}  users={s['ai']['distinct_users']}")
else:
    print("No anomalies flagged — nothing written.")
