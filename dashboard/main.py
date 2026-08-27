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
        "id":          f"rule:{hit['_id']}",
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


# ----------------------------------------------------------------- triage state
# Analyst workflow state (status / assignee / note / false-positive flag) lives
# in its own mutable index, keyed by the alert's stable id. Same pattern as the
# ai-responses audit index — a small side store the console owns, distinct from
# the immutable alert/detection documents.
TRIAGE_INDEX = "ai-alert-triage"
TRIAGE_STATES = ("new", "investigating", "resolved", "false_positive")


def _triage_map(alert_ids=None):
    """{alert_id: triage_doc} for the given ids (or all recent triage docs)."""
    try:
        if alert_ids:
            body = {"size": 1000, "query": {"ids": {"values": list(alert_ids)}}}
        else:
            body = {"size": 1000, "sort": [{"updated_at": {"order": "desc"}}]}
        res = client.search(index=TRIAGE_INDEX, body=body)
    except Exception:
        return {}
    return {h["_id"]: h["_source"] for h in res["hits"]["hits"]}


def _merge_triage(alerts):
    """Attach triage fields to a list of formatted alerts, in place."""
    tmap = _triage_map([a["id"] for a in alerts if a.get("id")])
    for a in alerts:
        t = tmap.get(a.get("id"))
        a["triage_status"] = (t or {}).get("status", "new")
        a["assignee"] = (t or {}).get("assignee")
        a["triage_note"] = (t or {}).get("note")
        a["false_positive"] = bool((t or {}).get("false_positive"))
    return alerts

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
        "alerts": _merge_triage([_fmt(h) for h in res["hits"]["hits"]]),
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
            "id":          f"ai:{h['_id']}",
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
    return {"count": res["hits"]["total"]["value"], "alerts": _merge_triage(out)}

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


@app.get("/api/response/blocked")
def blocked_ips():
    """Currently-blocked IPs, derived from the response audit log:
    executed blocks minus executed unblocks, latest state per (agent, ip)."""
    try:
        res = client.search(index=f"{RESPONSE_INDEX}-*", body={
            "size": 1000,
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": {"bool": {"filter": [
                {"terms": {"action": ["block-ip", "unblock-ip"]}},
                {"term": {"status": "executed"}},
            ]}},
        })
    except Exception:
        return {"blocked": []}

    state = {}
    for h in res["hits"]["hits"]:
        s = h["_source"]
        key = f"{s.get('agent_id')}|{s.get('srcip')}"
        if s.get("action") == "block-ip":
            state[key] = s
        else:
            state.pop(key, None)
    return {"blocked": [
        {"agent_id": v.get("agent_id"), "srcip": v.get("srcip"),
         "since": v.get("timestamp"), "alert_ref": v.get("alert_ref"),
         "reason": v.get("reason")}
        for v in state.values()
    ]}


class UnblockRequest(BaseModel):
    agent_id: str
    srcip: str
    reason: str | None = None


@app.post("/api/response/unblock-ip")
def unblock_ip(req: UnblockRequest):
    """Best-effort unblock. Wazuh has no first-class 'undo firewall-drop' over the
    manager API — this attempts the paired delete on the agent and always records
    the intent, so the blocked-IP view reflects the analyst's action even when the
    teardown has to be confirmed agent-side."""
    try:
        ipaddress.ip_address(req.srcip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"'{req.srcip}' is not a valid IP")

    audit_req = BlockRequest(agent_id=req.agent_id, srcip=req.srcip,
                             reason=req.reason or "manual unblock from dashboard")
    try:
        res = wazuh_api.unblock_ip(req.agent_id, req.srcip)
        wazuh_msg = res.get("message")
        detail = f"firewall-drop delete sent to agent {req.agent_id}"
    except Exception as e:
        wazuh_msg = None
        detail = (f"delete not confirmed ({e}); recorded as unblocked. If the drop "
                  "persists, remove it on the agent (iptables -D) or install the "
                  "firewall-drop delete active-response.")

    doc = _audit("unblock-ip", audit_req, "executed", detail)
    return {"ok": True, "wazuh": wazuh_msg, "audit": doc}


# ----------------------------------------------------------------- triage API

class TriageUpdate(BaseModel):
    alert_id: str
    status: str = "investigating"
    assignee: str | None = None
    note: str | None = None
    false_positive: bool = False
    alert_ref: str | None = None
    alert_timestamp: str | None = None
    alert_source: str | None = None


@app.get("/api/triage")
def triage_list(limit: int = 500):
    """Every triage record, newest first — feeds the metrics page and any
    'my queue' style views."""
    try:
        res = client.search(index=TRIAGE_INDEX, body={
            "size": limit,
            "sort": [{"updated_at": {"order": "desc"}}],
        })
    except Exception:
        return {"count": 0, "items": []}
    return {
        "count": res["hits"]["total"]["value"],
        "items": [{**h["_source"], "alert_id": h["_id"]}
                  for h in res["hits"]["hits"]],
    }


@app.post("/api/triage")
def triage_set(req: TriageUpdate):
    """Create or update the triage record for one alert (keyed by alert id)."""
    if req.status not in TRIAGE_STATES:
        raise HTTPException(status_code=400,
                            detail=f"status must be one of {list(TRIAGE_STATES)}")

    now = datetime.now(timezone.utc).isoformat()
    try:
        existing = client.get(index=TRIAGE_INDEX, id=req.alert_id)["_source"]
    except Exception:
        existing = {}

    doc = {
        "status": req.status,
        "assignee": req.assignee,
        "note": req.note,
        "false_positive": req.false_positive or req.status == "false_positive",
        "alert_ref": req.alert_ref or existing.get("alert_ref"),
        "alert_timestamp": req.alert_timestamp or existing.get("alert_timestamp"),
        "alert_source": req.alert_source or existing.get("alert_source"),
        "created_at": existing.get("created_at", now),
        "updated_at": now,
    }
    client.index(index=TRIAGE_INDEX, id=req.alert_id, body=doc, refresh=True)
    return {"ok": True, "alert_id": req.alert_id, "triage": doc}


# ----------------------------------------------------------------- metrics

def _category_agg(start_iso):
    try:
        res = client.search(index="ai-detections-*", body={
            "size": 0,
            "query": {"range": {"timestamp": {"gte": start_iso}}},
            "aggs": {"c": {"terms": {"field": "ai.category.keyword", "size": 20}}},
        })
        return [{"category": b["key"], "count": b["doc_count"]}
                for b in res["aggregations"]["c"]["buckets"]]
    except Exception:
        return []


@app.get("/api/alerts/by_category")
def by_category(hours: int = 168):
    """AI detections grouped by heuristic category — feeds the breakdown chart."""
    start = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    return {"categories": _category_agg(start)}


@app.get("/api/metrics")
def metrics(hours: int = 168):
    """The rule-vs-AI comparison plus SOC workflow metrics (FP rate, MTTR).
    This endpoint is the live version of the Claim B evidence table."""
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=hours)).isoformat()

    def _count(index, filters):
        try:
            return client.count(index=index,
                                body={"query": {"bool": {"filter": filters}}})["count"]
        except Exception:
            return 0

    rule_total = _count("wazuh-alerts-4.x-*", [
        {"range": {"timestamp": {"gte": start}}},
        {"range": {"rule.level": {"gte": 10}}},
    ])
    ai_total = _count("ai-detections-*", [{"range": {"timestamp": {"gte": start}}}])

    def _minutes(index, filters):
        try:
            res = client.search(index=index, body={
                "size": 0,
                "query": {"bool": {"filter": filters}},
                "aggs": {"m": {"date_histogram": {
                    "field": "timestamp", "fixed_interval": "1m", "min_doc_count": 1,
                }}},
            })
            return {b["key"] for b in res["aggregations"]["m"]["buckets"]}
        except Exception:
            return set()

    rule_min = _minutes("wazuh-alerts-4.x-*", [
        {"range": {"timestamp": {"gte": start}}},
        {"range": {"rule.level": {"gte": 10}}},
    ])
    ai_min = _minutes("ai-detections-*", [{"range": {"timestamp": {"gte": start}}}])

    try:
        tres = client.search(index=TRIAGE_INDEX, body={"size": 2000})
        tdocs = [h["_source"] for h in tres["hits"]["hits"]]
    except Exception:
        tdocs = []

    def _in_window(ts):
        return bool(ts) and ts >= start

    fp = sum(1 for t in tdocs
             if t.get("false_positive") and t.get("alert_source") == "ai"
             and _in_window(t.get("alert_timestamp")))

    resolve_secs = []
    for t in tdocs:
        if t.get("status") in ("resolved", "false_positive") \
           and _in_window(t.get("alert_timestamp")):
            try:
                a = datetime.fromisoformat(t["alert_timestamp"].replace("Z", "+00:00"))
                r = datetime.fromisoformat(t["updated_at"].replace("Z", "+00:00"))
                resolve_secs.append((r - a).total_seconds())
            except Exception:
                pass

    return {
        "window_hours": hours,
        "rule_alerts": rule_total,
        "ai_detections": ai_total,
        "overlap_minutes": {
            "both": len(rule_min & ai_min),
            "ai_only": len(ai_min - rule_min),
            "rule_only": len(rule_min - ai_min),
        },
        "false_positives": fp,
        "false_positive_rate": round(fp / ai_total, 3) if ai_total else 0.0,
        "mttr_seconds": round(sum(resolve_secs) / len(resolve_secs))
                        if resolve_secs else None,
        "triaged": len(tdocs),
        "by_category": _category_agg(start),
    }
