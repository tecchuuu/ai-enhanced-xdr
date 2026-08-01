from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from opensearchpy import OpenSearch

app = FastAPI(title="AI-XDR Dashboard API")

# allow the frontend (served from anywhere in dev) to call this API
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

client = OpenSearch(
    hosts=[{"host": "localhost", "port": 9200}],
    http_auth=("admin", "SecretPassword"),
    use_ssl=True, verify_certs=False, ssl_show_warn=False,
)

def _fmt(hit):
    s = hit["_source"]
    rule = s.get("rule", {})
    return {
        "timestamp":   s.get("@timestamp") or s.get("timestamp"),
        "rule_id":     rule.get("id"),
        "level":       rule.get("level"),
        "description": rule.get("description"),
        "agent":       s.get("agent", {}).get("name"),
        "srcip":       s.get("data", {}).get("srcip"),
        "srcuser":     s.get("data", {}).get("srcuser"),
        "source":      "rule",          # <-- the tag that separates rule vs AI
    }

@app.get("/api/health")
def health():
    return {"status": "ok", "cluster": client.info()["cluster_name"]}

@app.get("/api/alerts/rule")
def rule_alerts(limit: int = 50, min_level: int = 0):
    """Rule-based alerts from Wazuh."""
    body = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"range": {"rule.level": {"gte": min_level}}},
    }
    res = client.search(index="wazuh-alerts-4.x-*", body=body)
    return {
        "count": res["hits"]["total"]["value"],
        "alerts": [_fmt(h) for h in res["hits"]["hits"]],
    }

@app.get("/api/stats")
def stats():
    """Counts for the dashboard summary cards."""
    total = client.count(index="wazuh-alerts-4.x-*")["count"]
    agg = client.search(index="wazuh-alerts-4.x-*", body={
        "size": 0,
        "aggs": {"by_level": {"terms": {"field": "rule.level", "size": 20}}},
    })

    try:
        ai_total = client.count(index="ai-detections-*")["count"]
    except Exception:
        ai_total = 0
	
    return {
        "rule_alerts": total,
	"ai_alerts": ai_total,
        "by_level": {b["key"]: b["doc_count"]
                     for b in agg["aggregations"]["by_level"]["buckets"]},
    }

@app.get("/api/alerts/ai")
def ai_alerts(limit: int = 50):
    """AI-detected anomalies (source=morpheus_ai)."""
    try:
        res = client.search(index="ai-detections-*", body={
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
        })
    except Exception:
        return {"count": 0, "alerts": []}      # index may not exist yet

    out = []
    for h in res["hits"]["hits"]:
        s = h["_source"]
        out.append({
            "timestamp":   s.get("timestamp"),
            "rule_id":     s.get("rule", {}).get("id"),
            "level":       s.get("rule", {}).get("level"),
            "description": s.get("rule", {}).get("description"),
            "agent":       s.get("agent", {}).get("name"),
            "source":      "ai",
            "score":       s.get("ai", {}).get("anomaly_score"),
            "event_count": s.get("ai", {}).get("event_count"),
            "distinct_users": s.get("ai", {}).get("distinct_users"),
        })
    return {"count": res["hits"]["total"]["value"], "alerts": out}

@app.get("/api/alerts/combined")
def combined(limit: int = 100):
    """Both streams merged, newest first — what the dashboard renders."""
    rules = rule_alerts(limit=limit, min_level=10)["alerts"]   # 10+ = attack declaration
    ai    = ai_alerts(limit=limit)["alerts"]
    merged = sorted(rules + ai, key=lambda a: a["timestamp"] or "", reverse=True)
    return {
        "rule_count": len(rules),
        "ai_count":   len(ai),
        "alerts":     merged[:limit],
    }
