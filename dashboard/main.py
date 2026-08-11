import ipaddress
import os
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

load_dotenv()  # before wazuh_api reads its env vars

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from opensearchpy import OpenSearch
from pydantic import BaseModel

import wazuh_api

app = FastAPI(title="AI-XDR Dashboard API")

# allow the frontend (served from anywhere in dev) to call this API
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

client = OpenSearch(
    hosts=[{"host": os.environ.get("OS_HOST", "localhost"),
            "port": int(os.environ.get("OS_PORT", "9200"))}],
    http_auth=(os.environ.get("OS_USER", "admin"), os.environ.get("OS_PASS", "")),
    use_ssl=True, verify_certs=False, ssl_show_warn=False,
)

def _first(x):
    """Wazuh mitre fields are lists; take the first entry."""
    return x[0] if isinstance(x, list) and x else (x or None)


def _fmt(hit):
    s = hit["_source"]
    rule = s.get("rule", {})
    mitre = rule.get("mitre", {})
    groups = rule.get("groups") or []
    return {
        "timestamp":   s.get("@timestamp") or s.get("timestamp"),
        "rule_id":     rule.get("id"),
        "level":       rule.get("level"),
        "description": rule.get("description"),
        "agent":       s.get("agent", {}).get("name"),
        "srcip":       s.get("data", {}).get("srcip"),
        "srcuser":     s.get("data", {}).get("srcuser"),
        "source":      "rule",          # <-- the tag that separates rule vs AI
        # category: MITRE tactic when tagged, else the most specific rule group
        "category":    _first(mitre.get("tactic")) or (groups[-1] if groups else None),
        "mitre":       _first(mitre.get("id")),
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
        ai = s.get("ai", {})
        top_ips = ai.get("top_srcips") or []
        out.append({
            "timestamp":   s.get("timestamp"),
            "rule_id":     s.get("rule", {}).get("id"),
            "level":       s.get("rule", {}).get("level"),
            "description": s.get("rule", {}).get("description"),
            "agent":       s.get("agent", {}).get("name"),
            "source":      "ai",
            "score":       ai.get("anomaly_score"),
            "event_count": ai.get("event_count"),
            "distinct_users": ai.get("distinct_users"),
            "category":    ai.get("category"),
            "mitre":       ai.get("mitre"),
            "srcip":       top_ips[0]["ip"] if top_ips else None,
            "top_srcips":  top_ips,
        })
    return {"count": res["hits"]["total"]["value"], "alerts": out}

@app.get("/api/alerts/histogram")
def histogram(hours: int = 24, interval: str = "30m", min_level: int = 10):
    """Alert counts over time, split rule vs AI — feeds the overview time chart."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)

    def bucket_counts(index, extra_filters):
        body = {
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {"timestamp": {"gte": start.isoformat()}}},
                *extra_filters,
            ]}},
            "aggs": {"t": {"date_histogram": {
                "field": "timestamp",
                "fixed_interval": interval,
                "min_doc_count": 0,
                "extended_bounds": {
                    "min": int(start.timestamp() * 1000),
                    "max": int(now.timestamp() * 1000),
                },
            }}},
        }
        try:
            res = client.search(index=index, body=body)
            return {b["key"]: b["doc_count"]
                    for b in res["aggregations"]["t"]["buckets"]}
        except Exception:
            return {}

    rule = bucket_counts("wazuh-alerts-4.x-*",
                         [{"range": {"rule.level": {"gte": min_level}}}])
    ai = bucket_counts("ai-detections-*", [])
    keys = sorted(set(rule) | set(ai))
    return {"buckets": [
        {"time": k, "rule": rule.get(k, 0), "ai": ai.get(k, 0)} for k in keys
    ]}


@app.get("/api/alerts/top_srcips")
def top_srcips(hours: int = 24, size: int = 10):
    """Most active source IPs across all alert levels — feeds the overview bar chart."""
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"timestamp": {"gte": start.isoformat()}}},
            {"exists": {"field": "data.srcip"}},
        ]}},
        "aggs": {"ips": {"terms": {"field": "data.srcip", "size": size}}},
    }
    try:
        res = client.search(index="wazuh-alerts-4.x-*", body=body)
        return {"ips": [{"ip": b["key"], "count": b["doc_count"]}
                        for b in res["aggregations"]["ips"]["buckets"]]}
    except Exception:
        return {"ips": []}


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


# ----------------------------------------------------------------- response actions

RESPONSE_INDEX = "ai-responses"


@app.get("/api/agents")
def agents():
    """Agent inventory proxied from the Wazuh manager API."""
    try:
        return {"agents": wazuh_api.get_agents()}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh API unreachable: {e}")


class BlockRequest(BaseModel):
    agent_id: str
    srcip: str
    alert_ref: str | None = None   # what triggered this (rule id / detection desc)
    reason: str | None = None


def _audit(action, req, status, detail=""):
    doc = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "agent_id": req.agent_id,
        "srcip": req.srcip,
        "alert_ref": req.alert_ref,
        "reason": req.reason,
        "status": status,
        "detail": detail,
        "initiated_by": "dashboard",
    }
    idx = f"{RESPONSE_INDEX}-{datetime.now(timezone.utc):%Y.%m.%d}"
    client.index(index=idx, body=doc, refresh=True)
    return doc


@app.post("/api/response/block-ip")
def block_ip(req: BlockRequest):
    """Trigger firewall-drop active response on the agent, with guardrails."""
    try:
        ip = ipaddress.ip_address(req.srcip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"'{req.srcip}' is not a valid IP")

    # refuse blocks that would sever the agent's own plumbing
    if ip.is_loopback:
        _audit("block-ip", req, "refused", "loopback address")
        raise HTTPException(
            status_code=400,
            detail="Refusing to block a loopback address — that would drop the "
                   "agent's own local traffic. (Mock attacks from localhost are "
                   "not blockable; attack from another host to demo this.)",
        )

    try:
        res = wazuh_api.block_ip(req.agent_id, req.srcip)
    except Exception as e:
        _audit("block-ip", req, "failed", str(e))
        raise HTTPException(status_code=502, detail=f"Active response failed: {e}")

    doc = _audit("block-ip", req, "executed",
                 f"firewall-drop sent to agent {req.agent_id}")
    return {"ok": True, "wazuh": res.get("message"), "audit": doc}


@app.get("/api/response/log")
def response_log(limit: int = 100):
    """Audit trail of response actions taken from this console."""
    try:
        res = client.search(index=f"{RESPONSE_INDEX}-*", body={
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
        })
    except Exception:
        return {"count": 0, "actions": []}
    return {
        "count": res["hits"]["total"]["value"],
        "actions": [h["_source"] for h in res["hits"]["hits"]],
    }
